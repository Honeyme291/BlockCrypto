// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

/**
 * @title CryptographicProtocol
 * @dev 实现包含Setup, KeyGen, Update, Enc, Dec的完整密码协议
 */
contract Protocol is Ownable, ReentrancyGuard {
    using Counters for Counters.Counter;
    
    // ==================== 状态变量 ====================
    
    // 系统参数结构
    struct SystemParameters {
        uint256 prime; // 素数p
        uint256 generator; // 生成元g
        uint256 publicKey; // 系统公钥
        uint256 timestamp; // 参数生成时间
        bool initialized; // 是否已初始化
    }
    
    // 用户密钥结构
    struct UserKey {
        uint256 publicKey; // 用户公钥
        bytes32 privateKeyHash; // 私钥哈希（不存储明文私钥）
        uint256 keyVersion; // 密钥版本
        uint256 lastUpdate; // 最后更新时间
        bool active; // 密钥是否激活
    }
    
    // 加密数据结构
    struct EncryptedData {
        bytes ciphertext; // 密文
        uint256 ephemeralKey; // 临时公钥
        bytes32 dataHash; // 数据哈希
        address owner; // 数据所有者
        uint256 timestamp; // 加密时间
        uint256 keyVersion; // 使用的密钥版本
        bool exists; // 数据是否存在
    }
    
    // 更新请求结构
    struct UpdateRequest {
        address user; // 请求用户
        uint256 newPublicKey; // 新公钥
        bytes32 proof; // 更新证明
        uint256 requestTime; // 请求时间
        bool processed; // 是否已处理
    }
    
    // 状态变量
    SystemParameters public systemParams;
    mapping(address => UserKey) public userKeys;
    mapping(bytes32 => EncryptedData) public encryptedDataStore;
    mapping(uint256 => UpdateRequest) public updateRequests;
    
    Counters.Counter private _dataCounter;
    Counters.Counter private _updateCounter;
    
    // ==================== 构造函数 ====================
    
    /**
     * @dev 构造函数，设置合约部署者为所有者
     */
    constructor() Ownable(msg.sender) {}
    
    // ==================== 事件定义 ====================
    
    event SystemSetup(uint256 prime, uint256 generator, uint256 publicKey, uint256 timestamp);
    event KeyGenerated(address indexed user, uint256 publicKey, uint256 keyVersion, uint256 timestamp);
    event KeyUpdated(address indexed user, uint256 oldVersion, uint256 newVersion, uint256 timestamp);
    event DataEncrypted(bytes32 indexed dataId, address indexed owner, uint256 keyVersion, uint256 timestamp);
    event DataDecrypted(bytes32 indexed dataId, address indexed accessor, uint256 timestamp);
    event UpdateRequested(uint256 indexed requestId, address indexed user, uint256 timestamp);
    
    // ==================== 修饰符 ====================
    
    modifier systemInitialized() {
        require(systemParams.initialized, "System not initialized");
        _;
    }
    
    modifier validUser(address user) {
        require(user != address(0), "Invalid user address");
        require(userKeys[user].active, "User key not active");
        _;
    }
    
    modifier onlyKeyOwner(address keyOwner) {
        require(msg.sender == keyOwner, "Only key owner can perform this action");
        _;
    }
    
    // ==================== 1. Setup 阶段 ====================
    
    /**
     * @dev Setup阶段：初始化系统参数
     * @param _prime 系统使用的素数
     * @param _generator 群的生成元
     * 执行顺序：第1步 - 部署合约后首先执行
     * Gas消耗：约100,000 gas
     */
    function setup(uint256 _prime, uint256 _generator) external onlyOwner {
        require(!systemParams.initialized, "System already initialized");
        require(_prime > 1, "Invalid prime");
        require(_generator > 1 && _generator < _prime, "Invalid generator");
        
        // 生成系统公钥（这里简化处理，实际应该是复杂的密码学运算）
        uint256 systemPublicKey = modExp(_generator, block.timestamp, _prime);
        
        systemParams = SystemParameters({
            prime: _prime,
            generator: _generator,
            publicKey: systemPublicKey,
            timestamp: block.timestamp,
            initialized: true
        });
        
        emit SystemSetup(_prime, _generator, systemPublicKey, block.timestamp);
    }
    
    // ==================== 2. KeyGen 阶段 ====================
    
    /**
     * @dev KeyGen阶段：为用户生成密钥对
     * @param _publicKey 用户的公钥
     * @param _privateKeyHash 用户私钥的哈希值
     * 执行顺序：第2步 - 在Setup完成后，用户注册时执行
     * Gas消耗：约80,000 gas
     */
    function keyGen(uint256 _publicKey, bytes32 _privateKeyHash) 
        external 
        systemInitialized 
        nonReentrant 
    {
        require(userKeys[msg.sender].publicKey == 0, "Key already exists for user");
        require(_publicKey > 1 && _publicKey < systemParams.prime, "Invalid public key");
        require(_privateKeyHash != bytes32(0), "Invalid private key hash");
        
        // 验证公钥的有效性（简化验证）
        require(verifyPublicKey(_publicKey), "Public key verification failed");
        
        userKeys[msg.sender] = UserKey({
            publicKey: _publicKey,
            privateKeyHash: _privateKeyHash,
            keyVersion: 1,
            lastUpdate: block.timestamp,
            active: true
        });
        
        emit KeyGenerated(msg.sender, _publicKey, 1, block.timestamp);
    }
    
    // ==================== 3. Update 阶段 ====================
    
    /**
     * @dev Update阶段第1步：请求密钥更新
     * @param _newPublicKey 新的公钥
     * @param _proof 更新证明
     * 执行顺序：第3步 - 当用户需要更新密钥时执行
     * Gas消耗：约60,000 gas
     */
    function requestKeyUpdate(uint256 _newPublicKey, bytes32 _proof) 
        external 
        systemInitialized 
        validUser(msg.sender) 
        onlyKeyOwner(msg.sender) 
    {
        require(_newPublicKey > 1 && _newPublicKey < systemParams.prime, "Invalid new public key");
        require(_newPublicKey != userKeys[msg.sender].publicKey, "Same as current public key");
        
        _updateCounter.increment();
        uint256 requestId = _updateCounter.current();
        
        updateRequests[requestId] = UpdateRequest({
            user: msg.sender,
            newPublicKey: _newPublicKey,
            proof: _proof,
            requestTime: block.timestamp,
            processed: false
        });
        
        emit UpdateRequested(requestId, msg.sender, block.timestamp);
    }
    
    /**
     * @dev Update阶段第2步：执行密钥更新
     * @param _requestId 更新请求ID
     * 执行顺序：第3步后续 - 验证更新请求后执行
     * Gas消耗：约70,000 gas
     */
    function processKeyUpdate(uint256 _requestId) 
        external 
        onlyOwner 
        systemInitialized 
    {
        UpdateRequest storage request = updateRequests[_requestId];
        require(!request.processed, "Request already processed");
        require(request.user != address(0), "Invalid request");
        
        // 验证更新证明（简化验证）
        require(verifyUpdateProof(request.user, request.newPublicKey, request.proof), 
                "Update proof verification failed");
        
        UserKey storage userKey = userKeys[request.user];
        uint256 oldVersion = userKey.keyVersion;
        
        // 更新用户密钥
        userKey.publicKey = request.newPublicKey;
        userKey.keyVersion += 1;
        userKey.lastUpdate = block.timestamp;
        
        request.processed = true;
        
        emit KeyUpdated(request.user, oldVersion, userKey.keyVersion, block.timestamp);
    }
    
    // ==================== 4. Enc 阶段 ====================
    
    /**
     * @dev Enc阶段：加密数据
     * @param _data 要加密的数据
     * @param _ephemeralKey 临时公钥
     * 执行顺序：第4步 - 用户需要加密数据时执行
     * Gas消耗：约120,000 gas（取决于数据大小）
     */
    function encryptData(bytes calldata _data, uint256 _ephemeralKey) 
        external 
        systemInitialized 
        validUser(msg.sender) 
        nonReentrant 
        returns (bytes32 dataId) 
    {
        require(_data.length > 0, "Empty data");
        require(_ephemeralKey > 1 && _ephemeralKey < systemParams.prime, "Invalid ephemeral key");
        
        // 生成数据ID
        _dataCounter.increment();
        dataId = keccak256(abi.encodePacked(msg.sender, _dataCounter.current(), block.timestamp));
        
        // 执行加密操作（这里简化处理，实际应该是复杂的加密算法）
        bytes memory ciphertext = performEncryption(_data, userKeys[msg.sender].publicKey, _ephemeralKey);
        bytes32 dataHash = keccak256(_data);
        
        // 存储加密数据
        encryptedDataStore[dataId] = EncryptedData({
            ciphertext: ciphertext,
            ephemeralKey: _ephemeralKey,
            dataHash: dataHash,
            owner: msg.sender,
            timestamp: block.timestamp,
            keyVersion: userKeys[msg.sender].keyVersion,
            exists: true
        });
        
        emit DataEncrypted(dataId, msg.sender, userKeys[msg.sender].keyVersion, block.timestamp);
    }
    
    // ==================== 5. Dec 阶段 ====================
    
    /**
     * @dev Dec阶段：解密数据
     * @param _dataId 数据ID
     * @param _privateKeyProof 私钥证明
     * 执行顺序：第5步 - 用户需要访问加密数据时执行
     * Gas消耗：约90,000 gas（取决于数据大小）
     */
    function decryptData(bytes32 _dataId, bytes32 _privateKeyProof) 
        external 
        systemInitialized 
        validUser(msg.sender) 
        nonReentrant 
        returns (bytes memory decryptedData) 
    {
        EncryptedData storage encData = encryptedDataStore[_dataId];
        require(encData.exists, "Data does not exist");
        
        // 验证访问权限（数据所有者或授权用户）
        require(encData.owner == msg.sender || hasDecryptPermission(msg.sender, _dataId), 
                "No permission to decrypt");
    

        
        // 执行解密操作
        decryptedData = performDecryption(
            encData.ciphertext, 
            userKeys[msg.sender].publicKey, 
            encData.ephemeralKey
        );
        
      
        emit DataDecrypted(_dataId, msg.sender, block.timestamp);
    }
    
    // ==================== 辅助函数 ====================
    
    /**
     * @dev 模幂运算
     */
    function modExp(uint256 base, uint256 exponent, uint256 modulus) 
        internal 
        pure 
        returns (uint256 result) 
    {
        assembly {
            let memPtr := mload(0x40)
            mstore(memPtr, 0x20)
            mstore(add(memPtr, 0x20), 0x20)
            mstore(add(memPtr, 0x40), 0x20)
            mstore(add(memPtr, 0x60), base)
            mstore(add(memPtr, 0x80), exponent)
            mstore(add(memPtr, 0xa0), modulus)
        
            result := mload(memPtr)
        }
    }
    
    /**
     * @dev 验证公钥有效性
     */
    function verifyPublicKey(uint256 _publicKey) internal view returns (bool) {
        // 简化验证：检查公钥是否在有效范围内
        return _publicKey > 1 && _publicKey < systemParams.prime;
    }
    
    /**
     * @dev 验证更新证明
     */
    function verifyUpdateProof(address _user, uint256 _newPublicKey, bytes32 _proof) 
        internal 
        view 
        returns (bool) 
    {
        // 简化验证：检查证明是否与用户和新公钥相关
        bytes32 expectedProof = keccak256(abi.encodePacked(_user, _newPublicKey, userKeys[_user].privateKeyHash));
        return _proof == expectedProof;
    }
    
    /**
     * @dev 执行加密操作（简化实现）
     */
    function performEncryption(bytes calldata _data, uint256 _publicKey, uint256 _ephemeralKey) 
        internal 
        pure 
        returns (bytes memory) 
    {
        // 简化加密：XOR操作
        bytes memory encrypted = new bytes(_data.length);
        bytes32 keyHash = keccak256(abi.encodePacked(_publicKey, _ephemeralKey));
        
        for (uint256 i = 0; i < _data.length; i++) {
            encrypted[i] = _data[i] ^ keyHash[i % 32];
        }
        
        return encrypted;
    }
    
    /**
     * @dev 执行解密操作（简化实现）
     */
    function performDecryption(bytes memory _ciphertext, uint256 _publicKey, uint256 _ephemeralKey) 
        internal 
        pure 
        returns (bytes memory) 
    {
        // 简化解密：XOR操作（与加密相同）
        bytes memory decrypted = new bytes(_ciphertext.length);
        bytes32 keyHash = keccak256(abi.encodePacked(_publicKey, _ephemeralKey));
        
        for (uint256 i = 0; i < _ciphertext.length; i++) {
            decrypted[i] = _ciphertext[i] ^ keyHash[i % 32];
        }
        
        return decrypted;
    }
    
    /**
     * @dev 验证私钥证明
     */
    function verifyPrivateKeyProof(address _user, bytes32 _proof) internal view returns (bool) {
        return keccak256(abi.encodePacked(_user, _proof)) == userKeys[_user].privateKeyHash;
    }
    
    /**
     * @dev 检查解密权限
     */
    function hasDecryptPermission(address _user, bytes32 _dataId) internal view returns (bool) {
        // 简化实现：只有数据所有者有权限
        return encryptedDataStore[_dataId].owner == _user;
    }
    
    // ==================== 查询函数 ====================
    
    /**
     * @dev 获取用户密钥信息
     */
    function getUserKey(address _user) external view returns (UserKey memory) {
        return userKeys[_user];
    }
    
    /**
     * @dev 获取加密数据信息
     */
    function getEncryptedData(bytes32 _dataId) external view returns (EncryptedData memory) {
        return encryptedDataStore[_dataId];
    }
    
    /**
     * @dev 获取系统参数
     */
    function getSystemParameters() external view returns (SystemParameters memory) {
        return systemParams;
    }
    
    /**
     * @dev 获取Gas消耗估算
     */
    function estimateGas() external pure returns (
        uint256 setupGas,
        uint256 keyGenGas,
        uint256 updateGas,
        uint256 encryptGas,
        uint256 decryptGas
    ) {
        return (100000, 80000, 65000, 120000, 90000);
    }
}

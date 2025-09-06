// SPDX-License-Identifier: MIT
// Remix IDE 自动化测试脚本
// 文件名: deploy_and_test.js

const { expect } = require("chai");
const { ethers } = require("hardhat");

/**
 * 主测试函数 - 在Remix中运行
 * 完整演示密码协议的五个阶段
 */
async function main() {
    console.log("开始部署和测试密码协议...");
    console.log("=" .repeat(50));
    
    // 获取账户
    const [owner, user1, user2] = await ethers.getSigners();
    console.log("账户信息:");
    console.log("Owner:", owner.address);
    console.log("User1:", user1.address);
    console.log("User2:", user2.address);
    
    // ==================== 部署合约 ====================
    console.log("部署合约...");
    const CryptoProtocol = await ethers.getContractFactory("Protocol");
    const protocol = await CryptoProtocol.deploy();
    await protocol.deployed();
    console.log("合约已部署到:", protocol.address);
    console.log("部署Gas消耗:", (await protocol.deployTransaction.wait()).gasUsed.toString());
    
    // ==================== 阶段1: Setup ====================
    console.log("🔧 阶段1: 系统初始化 (Setup)");
    console.log("-".repeat(30));
    
    const setupTx = await protocol.connect(owner).setup(23, 5);
    const setupReceipt = await setupTx.wait();
    console.log("Setup完成");
    console.log("Gas消耗:", setupReceipt.gasUsed.toString());
    
    // 验证系统状态
    const systemParams = await protocol.getSystemParameters();
    console.log("系统参数:");
    console.log("  - Prime:", systemParams.prime.toString());
    console.log("  - Generator:", systemParams.generator.toString());
    console.log("  - System Public Key:", systemParams.publicKey.toString());
    console.log("  - Initialized:", systemParams.initialized);
    
    // ==================== 阶段2: KeyGen ====================
    console.log("🔑 阶段2: 密钥生成 (KeyGen)");
    console.log("-".repeat(30));
    
    // User1生成密钥
    const user1PublicKey = 12;
    const user1PrivateKeyHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("user1_private_key"));
    
    const keyGenTx = await protocol.connect(user1).keyGen(user1PublicKey, user1PrivateKeyHash);
    const keyGenReceipt = await keyGenTx.wait();
    console.log("User1密钥生成完成");
    console.log("Gas消耗:", keyGenReceipt.gasUsed.toString());
    
    // 验证用户密钥
    const user1Key = await protocol.getUserKey(user1.address);
    console.log("User1密钥信息:");
    console.log("Public Key:", user1Key.publicKey.toString());
    console.log("Key Version:", user1Key.keyVersion.toString());
    console.log("Active:", user1Key.active);
    
    // User2也生成密钥
    const user2PublicKey = 15;
    const user2PrivateKeyHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("user2_private_key"));
    
    await protocol.connect(user2).keyGen(user2PublicKey, user2PrivateKeyHash);
    console.log("User2密钥生成完成");
    
    // ==================== 阶段3: Update ====================
    console.log("🔄 阶段3: 密钥更新 (Update)");
    console.log("-".repeat(30));
    
    let processReceipt = null;
    const newPublicKey = 18;
    // 生成更新证明 - 使用合约中相同的验证逻辑
    const expectedProof = ethers.utils.keccak256(
        ethers.utils.defaultAbiCoder.encode(
            ["address", "uint256", "bytes32"],
            [user1.address, newPublicKey, user1PrivateKeyHash]
        )
    );
    
    console.log("更新证明:", expectedProof);
    
    const requestTx = await protocol.connect(user1).requestKeyUpdate(newPublicKey, expectedProof);
    const requestReceipt = await requestTx.wait();
    console.log("User1密钥更新请求完成");
    console.log("Gas消耗:", requestReceipt.gasUsed.toString());
    
    // 检查更新请求状态
    const updateRequest = await protocol.updateRequests(1);
    console.log("更新请求状态:");
    console.log("  - User:", updateRequest.user);
    console.log("  - New Public Key:", updateRequest.newPublicKey.toString());
    console.log("  - Processed:", updateRequest.processed);
    
    // 处理更新请求 - 添加手动gas限制
    try {
        const processTx = await protocol.connect(owner).processKeyUpdate(1, {
            gasLimit: 200000 // 手动设置gas限制
        });
        processReceipt = await processTx.wait();
        console.log("User1密钥更新处理完成");
        console.log("Gas消耗:", processReceipt.gasUsed.toString());
        
        // 验证更新后的密钥
        const updatedKey = await protocol.getUserKey(user1.address);
        console.log("更新后的User1密钥:");
        console.log("New Public Key:", updatedKey.publicKey.toString());
        console.log("New Version:", updatedKey.keyVersion.toString());
    } catch (error) {
        console.log("❌ 密钥更新处理失败:", error.message);
        console.log("跳过更新阶段，继续测试加密解密...");
    }
    
    // ==================== 阶段4: Enc ====================
    console.log("🔒 阶段4: 数据加密 (Enc)");
    console.log("-".repeat(30));
    
    // 准备测试数据
    const testMessage = "Hello Blockchain!";
    const testData = ethers.utils.toUtf8Bytes(testMessage);
    const ephemeralKey = 8;
    
    console.log("原始数据:", testMessage);
    console.log("数据长度:", testData.length, "字节");
    
    const encryptTx = await protocol.connect(user1).encryptData(testData, ephemeralKey);
    const encryptReceipt = await encryptTx.wait();
    console.log("数据加密完成");
    console.log("Gas消耗:", encryptReceipt.gasUsed.toString());
    
    // 从事件中获取dataId
    const encryptEvent = encryptReceipt.events.find(e => e.event === 'DataEncrypted');
    const dataId = encryptEvent.args.dataId;
    console.log("加密信息:");
    console.log("Data ID:", dataId);
    console.log("Owner:", encryptEvent.args.owner);
    
    // ==================== 阶段5: Dec ====================
    console.log("🔓 阶段5: 数据解密 (Dec)");
    console.log("-".repeat(30));
    
    let decryptReceipt = null;
    // 生成私钥证明 - 使用合约中相同的验证逻辑
    const privateKeyProof = ethers.utils.keccak256(
        ethers.utils.defaultAbiCoder.encode(
            ["address", "bytes32"],
            [user1.address, user1PrivateKeyHash]
        )
    );
    
    console.log("私钥证明:", privateKeyProof);
    
    try {
        // 使用 callStatic 来获取返回值
        const decryptedBytes = await protocol.connect(user1).callStatic.decryptData(dataId, privateKeyProof, {
            gasLimit: 300000
        });
        const decryptedMessage = ethers.utils.toUtf8String(decryptedBytes);
        
        console.log("解密结果:");
        console.log("解密数据:", decryptedMessage);
        console.log("数据匹配:", decryptedMessage === testMessage ? "✅ 成功" : "❌ 失败");
        
        // 实际执行解密交易
        const decryptTx = await protocol.connect(user1).decryptData(dataId, privateKeyProof, {
            gasLimit: 300000
        });
        decryptReceipt = await decryptTx.wait();
        console.log("数据解密交易完成");
        console.log("Gas消耗:", decryptReceipt.gasUsed.toString());
    } catch (error) {
        console.log("❌ 解密失败:", error.message);
        
        // 尝试直接查看加密数据
        const encryptedData = await protocol.getEncryptedData(dataId);
        console.log("加密数据信息:");
        console.log("  - Owner:", encryptedData.owner);
        console.log("  - Key Version:", encryptedData.keyVersion.toString());
        console.log("  - Exists:", encryptedData.exists);
    }
    
    // ==================== 性能统计 ====================
    console.log("📊 性能统计报告");
    console.log("=".repeat(50));
    
    console.log(
        "操作类型".padEnd(15) +
        "|" +
        "Gas消耗".padEnd(12) +
        "|" +
        "说明".padEnd(15)
    );
    console.log("-".repeat(50));

    console.log(
        "Setup".padEnd(15) +
        "|" +
        setupReceipt.gasUsed.toString().padEnd(12) +
        "|" +
        "系统初始化".padEnd(15)
    );

    console.log(
        "KeyGen".padEnd(15) +
        "|" +
        keyGenReceipt.gasUsed.toString().padEnd(12) +
        "|" +
        "密钥生成".padEnd(15)
    );

    console.log(
        "UpdateReq".padEnd(15) +
        "|" +
        requestReceipt.gasUsed.toString().padEnd(12) +
        "|" +
        "更新请求".padEnd(15)
    );


    console.log(
        "Encrypt".padEnd(15) +
        "|" +
        encryptReceipt.gasUsed.toString().padEnd(12) +
        "|" +
        "数据加密".padEnd(15)
    );

    if (decryptReceipt) {
        console.log(
            "Decrypt".padEnd(15) +
            "|" +
            decryptReceipt.gasUsed.toString().padEnd(12) +
            "|" +
            "数据解密".padEnd(15)
        );
    } else {
        console.log(
            "Decrypt".padEnd(15) +
            "|" +
            N/A +
            "|" +
             "数据解密".padEnd(15)
        );
    }

    console.log("=".repeat(50));
    
    // ==================== 简单功能测试 ====================
    console.log("🧪 简单功能测试");
    console.log("-".repeat(30));
    
    // 测试多个数据加密
    try {
        const testMessages = ["Test1", "Test2", "Test3"];
        for (let i = 0; i < testMessages.length; i++) {
            const data = ethers.utils.toUtf8Bytes(testMessages[i]);
            const tx = await protocol.connect(user1).encryptData(data, 10 + i, {
                gasLimit: 150000
            });
            const receipt = await tx.wait();
            console.log(`✅ 数据 "${testMessages[i]}" 加密成功, Gas: ${receipt.gasUsed}`);
        }
    } catch (error) {
        console.log("❌ 多数据加密测试失败:", error.message);
    }
    
    // 测试数据查询功能
    try {
        const userKeyInfo = await protocol.getUserKey(user1.address);
        console.log("✅ 用户密钥查询成功");
        
        const systemInfo = await protocol.getSystemParameters();
        console.log("✅ 系统参数查询成功");
        
        const encryptedInfo = await protocol.getEncryptedData(dataId);
        console.log("✅ 加密数据查询成功");
    } catch (error) {
        console.log("❌ 查询功能测试失败:", error.message);
    }
    
    console.log("测试完成!");
    console.log("=" .repeat(50));
}

// 错误处理
main()
    .then(() => {
        console.log("脚本执行成功");
        process.exit(0);
    })
    .catch((error) => {
        console.error("脚本执行成功:");
        console.error(error);
        process.exit(1);
    });

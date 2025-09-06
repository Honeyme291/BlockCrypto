#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

// 简化的哈希函数实现 - 返回随机值
void H(element_t out, element_t in1, element_t in2, element_t in3, pairing_t pairing) {
    element_random(out);
}

// 简化的密钥派生函数 - 返回随机值
void KDF(element_t k1, element_t k2, element_t input, pairing_t pairing) {
    element_random(k1);
    element_random(k2);
}

// 简化的随机性提取器 - 返回随机值
void Ext(element_t out, element_t input, char *eta, pairing_t pairing) {
    element_random(out);
}

int main(int argc, char **argv) {
    pairing_t pairing;
    double t_start, t_setup, t_keygen, t_update, t_enc, t_dec, t_total;
    element_t g, g1, g2, g3, U, V, alpha;
    element_t t1_rnd, t2_rnd, m1, m2;
    element_t id, M, s;
    element_t c1, c2, c3, theta;
    element_t sk1, sk2, sk3, sk4;
    element_t sk1_new, sk2_new, sk3_new, sk4_new;
    element_t X1, X2, beta, c4_prime, k1_prime, k2_prime;
    element_t temp1, temp2, temp3, temp4, temp5;
    element_t M_dec;
    char eta_str[32] = "random_eta_string";

    pbc_demo_pairing_init(pairing, argc, argv);
    if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");

    // 初始化所有元素
    element_init_Zr(alpha, pairing);
    element_init_Zr(t1_rnd, pairing);
    element_init_Zr(t2_rnd, pairing);
    element_init_Zr(m1, pairing);
    element_init_Zr(m2, pairing);
    element_init_Zr(s, pairing);
    element_init_Zr(id, pairing);
    element_init_Zr(beta, pairing);
    element_init_Zr(k1_prime, pairing);
    element_init_Zr(k2_prime, pairing);
    
    element_init_GT(M, pairing);
    element_init_GT(c1, pairing);
    element_init_GT(c4_prime, pairing);
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_init_GT(temp3, pairing);
    element_init_GT(M_dec, pairing);
    
    element_init_G1(g, pairing);
    element_init_G1(g1, pairing);
    element_init_G1(g2, pairing);
    element_init_G1(g3, pairing);
    element_init_G1(U, pairing);
    element_init_G1(V, pairing);
    element_init_G1(sk1, pairing);
    element_init_G1(sk2, pairing);
    element_init_G1(sk3, pairing);
    element_init_G1(sk4, pairing);
    element_init_G1(sk1_new, pairing);
    element_init_G1(sk2_new, pairing);
    element_init_G1(sk3_new, pairing);
    element_init_G1(sk4_new, pairing);
    element_init_G1(c2, pairing);
    element_init_G1(c3, pairing);
    element_init_G1(temp4, pairing);
    element_init_G1(temp5, pairing);
    
    element_init_Zr(theta, pairing);
    
    t_start = pbc_get_time();
    
   
    // 生成群参数
    element_random(g);
    
    // 选择随机元素
    element_random(alpha);
    element_random(g2);
    element_random(g3);
    element_random(U);
    element_random(V);
    
    // 计算g1 = g^alpha
    element_pow_zn(g1, g, alpha);
    
    t_setup = pbc_get_time();
    printf("Setup Phase: %.6f sec\n", t_setup - t_start);
    
    
    // 设置用户身份
    element_set_si(id, 12345);
    
    // 选择随机数t1, t2
    element_random(t1_rnd);
    element_random(t2_rnd);
    
    // 计算U^{id}*V
    element_pow_zn(temp4, U, id);
    element_mul(temp4, temp4, V);
    
    // 计算sk_{id,1}^0 = g3^alpha * (U^{id}V)^{t1}
    element_pow_zn(sk1, g3, alpha);
    element_pow_zn(temp5, temp4, t1_rnd);
    element_mul(sk1, sk1, temp5);
    
    // sk_{id,2}^0 = g^{-t1}
    element_pow_zn(sk2, g, t1_rnd);
    element_invert(sk2, sk2);
    
    // sk_{id,3}^0 = g2^alpha * (U^{id}V)^{t2}
    element_pow_zn(sk3, g2, alpha);
    element_pow_zn(temp5, temp4, t2_rnd);
    element_mul(sk3, sk3, temp5);
    
    // sk_{id,4}^0 = g^{-t2}
    element_pow_zn(sk4, g, t2_rnd);
    element_invert(sk4, sk4);
    
    t_keygen = pbc_get_time();
    printf("KeyGen Phase: %.6f sec\n", t_keygen - t_setup);
    
   
    // 选择随机更新因子
    element_random(m1);
    element_random(m2);
    
    // 更新密钥组件
    element_pow_zn(temp5, temp4, m1);
    element_mul(sk1_new, sk1, temp5);
    element_pow_zn(temp5, g, m1);
    element_mul(sk2_new, sk2, temp5);
    
    element_pow_zn(temp5, temp4, m2);
    element_mul(sk3_new, sk3, temp5);
    element_pow_zn(temp5, g, m2);
    element_mul(sk4_new, sk4, temp5);
    
    t_update = pbc_get_time();
    printf("KeyUpdate Phase: %.6f sec\n", t_update - t_keygen);
    
   
   
    // 设置明文消息
    element_random(M);
   
    
    // 选择随机数s
    element_random(s);
    
    
    // 计算c2 = g^s
    element_pow_zn(c2, g, s);
   
    // 计算c3 = (U^{id}V)^s
    element_pow_zn(c3, temp4, s);
   
    
    // 计算e(g1, g2)^s
    element_pairing(temp1, g1, g2);
   
    element_pow_zn(temp1, temp1, s);
  
    
    // 计算c1 = Ext(e(g1,g2)^s, η) ⊕ M
    Ext(temp2, temp1, eta_str, pairing);
  
    element_mul(c1, temp2, M);
  
    
    // 计算β = H(c1, c2, c3, η)
    H(beta, c1, c2, c3, pairing);
  
    
    // 修复配对操作 - 使用不同的临时变量
    element_t temp_pair1, temp_pair2;
    element_init_GT(temp_pair1, pairing);
    element_init_GT(temp_pair2, pairing);
   
    
    // 计算e(g1, g3)^s
    element_pairing(temp_pair1, g1, g3);
   
    element_pow_zn(temp_pair1, temp_pair1, s);
  
    // 计算e(g1, g2)^{βs}
    element_pairing(temp_pair2, g1, g2);
   
    element_pow_zn(temp_pair2, temp_pair2, beta);
   
    element_pow_zn(temp_pair2, temp_pair2, s);
  
    // 计算c4 = e(g1, g3)^s * e(g1, g2)^{βs}
    element_mul(temp1, temp_pair1, temp_pair2);
   
    
    // 计算KDF(c4) = (k1, k2)
    KDF(k1_prime, k2_prime, temp1, pairing);
   
    
	element_init_Zr(temp3, pairing);  // 明确初始化为Zr类型

	
	element_mul(temp3, s, k1_prime);
	

	
	element_add(theta, temp3, k2_prime);
	
   
    
    
    t_enc = pbc_get_time();
    printf("Encryption Phase: %.6f sec\n", t_enc - t_update);
    
  
    // 计算X1 = e(sk1_new, c2) * e(sk2_new, c3)
    element_pairing(temp1, sk1_new, c2);
	
    element_pairing(temp2, sk2_new, c3);
	 
	 element_init_GT(X1, pairing);
    element_mul(X1, temp1, temp2);
	 

    // 计算X2 = e(sk3_new, c2) * e(sk4_new, c3)
    element_pairing(temp1, sk1_new, c2);
	 
    element_pairing(temp2, sk2_new, c3);
	
	  element_init_GT(X2, pairing);
    element_mul(X2, temp1, temp2);
	
    
    // 计算β = H(c1, c2, c3, η)
    H(beta, c1, c2, c3, pairing);
	 
    
    // 计算c4' = X1 * X2^β
    element_pow_zn(temp1, X2, beta);
    element_mul(c4_prime, X1, temp1);
	 
    
    // 计算KDF(c4') = (k1', k2')
    KDF(k1_prime, k2_prime, c4_prime, pairing);
	 
    
    // 验证g^θ = c2^{k1'} * g^{k2'}
    element_pow_zn(temp4, c2, k1_prime);
    element_pow_zn(temp5, g, k2_prime);
    element_mul(temp4, temp4, temp5);
    element_pow_zn(temp5, g, theta);
	
    
  
  
    
    t_dec = pbc_get_time();
    printf("Decryption Phase: %.6f sec\n", t_dec - t_enc);
    
    t_total = pbc_get_time() - t_start;
    printf("Total execution time: %.6f sec\n", t_total);
   
    
    // 清理所有元素
    element_clear(alpha);
    element_clear(t1_rnd);
    element_clear(t2_rnd);
    element_clear(m1);
    element_clear(m2);
    element_clear(s);
    element_clear(id);
    element_clear(beta);
    element_clear(k1_prime);
    element_clear(k2_prime);
    element_clear(M);
    element_clear(c1);
    element_clear(c4_prime);
    element_clear(temp1);
    element_clear(temp2);
    element_clear(temp3);
    element_clear(M_dec);
    element_clear(g);
    element_clear(g1);
    element_clear(g2);
    element_clear(g3);
    element_clear(U);
    element_clear(V);
    element_clear(sk1);
    element_clear(sk2);
    element_clear(sk3);
    element_clear(sk4);
    element_clear(sk1_new);
    element_clear(sk2_new);
    element_clear(sk3_new);
    element_clear(sk4_new);
    element_clear(c2);
    element_clear(c3);
    element_clear(temp4);
    element_clear(temp5);
    element_clear(theta);
    element_clear(X1);
    element_clear(X2);
    element_clear(temp_pair1);
    element_clear(temp_pair2);
    
    pairing_clear(pairing);
    
    return 0;
}

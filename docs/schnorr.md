# schnorr签名算法

### 初始化
p: 有限域的阶 <br>
G: 椭圆曲线基点 <br>
N: 椭圆曲线的阶 <br>

### 密钥生成
生成256位随机数r <br>
d = r mod N, d就是用户私钥 <br>
P = dG, P就是用户公钥  <br>

### 签名验证
#### 签名
输入: 数据msg, 私钥d <br>
计算 P = d*G <br>
计算 k = getK(msg, d) <br>
计算 R = k*G <br>
计算 e = getE(P, R, msg) <br>
计算 s = (k + e*d) mod N <br>
输出签名: (R,s), 其中R为压缩格式的点 <br>

#### 验签
输入: 数据msg, 公钥P, 签名(R,s) <br>
计算 e = getE(P, R, msg) <br>
计算 X = s*G <br>
计算 Y = e*P <br>
计算 R' = X - Y = s*G - e*P <br>
如果 R' 等于 R, 则验证成功 <br>

#### 公式
##### getK(msg, d)
k可以是随机数，也可以由 msg和d分散计算. <br>
本方案中如下： <br>
计算 P = d*G, 其中Px, Py为P的坐标 <br>
计算 hmac = hmac512(Px, Py||msg)  <br>
取 hmac的前32字节, 得到h  <br>
计算 k = (d + h) mod N <br>

##### getE(P, R, msg)
e = sha256(R||P||msg) , P和R均为33字节压缩格式 <br>

##### 证明
R' = X - Y = s*G - e*P = (k + e*d)*G - e*d*G = k*G  <br>
R = k*G        <br>
所以 R'等于R <br>


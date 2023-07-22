from random import choice
from gmssl import sm3,func
#根据SM2椭圆曲线公钥密码算法推荐曲线参数进行初始化
#椭圆曲线方程:y^2=x^3+a*x+b
a=int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',16)
b=int('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',16)
p=int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',16)
n=int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',16)
#密钥对生成

#随机产生字符串,OK
def random_string(strlen):
    letterlist=['0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F']
    strl=""
    for i in range(strlen):
        temp=choice(letterlist)
        strl+=temp
    return strl
#椭圆曲线点的计算

#倍点,OK
def doublepoint(point,length):
    l=len(point)
    len_2=2*length
    if l<len_2:
        return None
    else:
        x1=int(point[0:length],16)
        y1=int(point[length:len_2],16)
        if l==len_2:
            z1=1
        else:
            z1=int(point[len_2:],16)
        T6=(z1*z1)%p
        T2=(y1*y1)%p
        T3=(x1+T6)%p
        T4=(x1-T6)%p
        T1=(T3*T4)%p
        T3=(y1*z1)%p
        T4=(T2*8)%p
        T5=(x1*T4)%p
        T1=(T1*3)%p
        T6=(T6*T6)%p
        T6=(((a+3)%p)*T6)%p
        T1=(T1+T6)%p
        z3=(T3+T3)%p
        T3=(T1*T1)%p
        T2=(T2*T4)%p
        x3=(T3-T5)%p
        if (T5%2)==1:
            T4=(T5+((T5+p)>>1)-T3)%p
        else:
            T4=(T5+(T5>>1)-T3)%p
        T1=(T1*T4)%p
        y3=(T1-T2)%p
        form='%%0%dx'%length
        form=form*3
        return form%(x3,y3,z3)

#点加,OK
def addpoint(p1,p2,length):
    len_2=2*length
    l1=len(p1)
    l2=len(p2)
    if (l1<len_2) or (l2<len_2):
        return None
    else:
        x1=int(p1[0:length],16)
        y1=int(p1[length:len_2],16)
        if (l1==len_2):
            z1=1
        else:
            z1=int(p1[len_2:],16)
        x2=int(p2[0:length],16)
        y2=int(p2[length:len_2],16)
        T1=(z1*z1)%p
        T2=(y2*z1)%p
        T3=(x2*T1)%p
        T1=(T1*T2)%p
        T2=(T3-x1)%p
        T3=(T3+x1)%p
        T4=(T2*T2)%p
        T1=(T1-y1)%p
        z3=(z1*T2)%p
        T2=(T2*T4)%p
        T3=(T3*T4)%p
        T5=(T1*T1)%p
        T4=(x1*T4)%p
        x3=(T5-T3)%p
        T2=(y1*T2)%p
        T3=(T4-x3)%p
        T1=(T1*T3)%p
        y3=(T1-T2)%p
        form='%%0%dx'%length
        form=form*3
        return form%(x3,y3,z3)

#Jacobian加重射影坐标转换成仿射坐标,OK
def convertJacb2Nor(point,length):
    len_2=length*2
    x=int(point[0:length],16)
    y=int(point[length:len_2],16)
    z=int(point[len_2:],16)
    z_inv=pow(z,p-2,p)
    z_invSquar=(z_inv*z_inv)%p
    z_invQube=(z_invSquar*z_inv)%p
    x_new=(x*z_invSquar)%p
    y_new=(y*z_invQube)%p
    z_new=(z*z_inv)%p
    if z_new==1:
        form='%%0%dx'%length
        form=form*2
        return form%(x_new,y_new)
    else:
        print("point at infinity!!!")
        return None
    '''form='%%0%dx'%length
    form=form*2
    return form%(x_new,y_new)'''
    
#kp,点乘,OK
def kp(k,point,length):
    point='%s%s'%(point,'1')
    #print("point",point)
    mask_str='8'
    for i in range(length-1):
        mask_str+='0'
    #print("mask_str",mask_str)
    mask=int(mask_str,16)
    temp=point
    flag=False
    for n in range(length*4):
        if (flag):
            temp=doublepoint(temp,length)
        if (k&mask)!=0:
            if(flag):
                temp=addpoint(temp,point,length)
            else:
                flag=True
                temp=point
        k=k<<1
    return convertJacb2Nor(temp,length)    
#签名算法
#十六进制转换为byte数组
def hex_byte(msg):
    ml=len(msg)
    if ml%2!=0:
        msg='0'+msg
    ml=int(len(msg)/2)
    msg_byte=[]
    for i in range(ml):
        msg_byte.append(int(msg[i*2:i*2+2],16))
    return msg_byte
#预处理1,计算z值
def pre1(PA):
    data='001031323334353637383132333435363738'
    data+=str(a)
    data+=str(b)
    data+=Q
    data+=PA
    #print("data",data)
    data_byte=hex_byte(data)
    return sm3.sm3_hash(data_byte)
#预处理2,得到杂凑值H,z：z值  m:消息
def pre2(z,m):
    data=z+m
    data_byte=hex_byte(data)
    return sm3.sm3_hash(data_byte)
#生成签名，E:消息的hash值，dA:签名者的私钥，K：随机数
def sign(E,dA,K,length,hexstr=0):
    if hexstr:
        e=int(E,16)
    else:
        E=E.encode('utf-8')
        E=E.hex()
        e=int(E,16)
    d=int(dA,16)
    k=int(K,16)
    p1=kp(k,Q,length)
    x=int(p1[0:length],16)
    R=((e+x)%n)
    if R==0 or R+k==n:
        return None
    d_1=pow(d+1,n-2,n)
    S=(d_1*(k+R)-R)%n
    if S==0:
        return None
    else:
        return '%064x%064x'%(R,S)
#验证签名,sign：签名R||S,E:消息的hash值，PA：公钥
def verify(sign,E,PA,length):
    r=int(sign[0:length],16)
    s=int(sign[length:2*length],16)
    e=int(E,16)
    t=(r+s)%n
    if t==0:
        return None
    p1=kp(s,Q,length)
    p2=kp(t,PA,length)
    if p1==p2:
        p1='%s%s'%(p1,1)
        p1=doublepoint(p1,length)
    else:
        p1='%s%s'%(p1,1)
        p1=addpoint(p1,p2,length)
        p1=convertJacb2Nor(p1,length)
    x=int(p1[0:length],16)
    return (r==((e+x)%n))
#加解密
#加密,m:消息，PA:公钥
def encrypt(m,PA,length,hexstr=0):
    if hexstr:
        message=m
    else:
        message=m.encode('utf-8')
        message=message.hex()
    k=random_string(length)
    #计算C1
    C1=kp(int(k,16),Q,length)
    xy=kp(int(k,16),PA,length)
    x2=xy[0:length]
    y2=xy[length:length*2]
    ml=len(message)
    #计算t
    XY=xy.encode('utf8')
    t=sm3.sm3_kdf(XY,ml/2)
    if int(t,16)==0:
        return None
    else:
        form='%%0%dx'%ml
        C2=form%(int(message,16)^int(t,16))
        data=x2+message+y2
        data_byte=hex_byte(data)
        C3=sm3.sm3_hash(data_byte)
        return '%s%s%s'%(C1,C3,C2)
#解密,C：密文，DA:私钥
def decrypt(C,DA,length):
    len_2=2*length
    len_3=len_2+64
    C1=C[0:len_2]
    C3=C[len_2:len_3]
    C2=C[len_3:]
    xy=kp(int(DA,16),C1,length)
    x2=xy[0:length]
    y2=xy[length:len_2]
    cl=len(C2)
    XY=xy.encode('utf8')
    t=sm3.sm3_kdf(XY,cl/2)
    if int(t,16)==0:
        return None
    else:
        form='%%0%dx'% cl
        m=form%(int(C2,16)^int(t,16))
        data=x2+m+y2
        data_byte=hex_byte(data)
        u=sm3.sm3_hash(data_byte)
        if (u==C3):
            return m
        else:
            return None

if __name__=='__main__':
    length=int(64)
    #d:SM2私钥,256bits
    #Q:SM2公钥,基点G：x||y
    d=random_string(length)
    Q='32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'
    #k:随机数
    #print("length",length)
    k=random_string(length)
    #print("k:",k)
    Pa=kp(int(d,16),Q,length)
    #print("Pa:",Pa)
    z1=pre1(Pa)
    print("z1:",z1)
    m='665165adbcfe5'
    hash_M=pre2(z1,m)
    print("hash_M：",hash_M)
    sig=sign(hash_M,d,k,length,1)
    print("sig:",sig)
    print(verify(sig,hash_M,Pa,length))
    C=encrypt(m,Pa,length,1)
    print('C:',C)
    M=decrypt(C,d,length)
    print("M:",M)
    
    
                    

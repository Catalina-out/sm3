import os
from ctypes import *
import base64

# dll = CDLL("D:/code/2020/pythonApi/fmapiv100（64位）.dll")
# 备注 Centos 操作系统需要密码机配置文件 /etc/FMDevice.conf
dll = CDLL("/usr/lib/python2.7/site-packages/libfmapiv100.so")
hDev = c_void_p()


def openDevice():
    pu8Id = c_char_p(b'12345678')
    u32Type = c_uint(0)
    u32Flag = c_uint(0)
    rv = dll.FM_CPC_OpenDevice(pu8Id, u32Type, u32Flag, byref(hDev))
    if rv != 0:
        print("FM_CPC_OpenDevice error! rv=%08x" % rv)
        return -1
    return 0


def closeDevice():
    rv = dll.FM_CPC_CloseDevice(hDev)
    if rv != 0:
        print("FM_CPC_CloseDevice error! rv=%08x" % rv)
        return -1
    return 0


def doSM3(indata):
    pu8ID = c_char_p(b"1234567812345678")
    u32IDlen = c_uint(16)
    # SM3杂凑算法第一步,运算初始化
    rv = dll.FM_CPC_SM3Init(hDev, None, pu8ID, u32IDlen)
    if rv != 0:
        print("FM_CPC_SM3Init error! rv=%08x" % rv)
        return str(rv)
    oneceLen = 16 * 1024
    ibegin = 0
    inAllLen = len(indata)
    bOver = False
    while 1:
        if(ibegin + oneceLen) > inAllLen:
            au8data = indata[ibegin:].encode("utf-8")
            # print("benginid:%d enddata:%s" % (ibegin, au8data))
            inLen = inAllLen - ibegin
            bOver = True
        else:
            au8data = indata[ibegin: ibegin + oneceLen].encode("utf-8")
            # print("benginid:%d data:%s" % (ibegin, au8data))
            ibegin += oneceLen
            inLen = oneceLen
        u32InLen = c_uint(inLen)
        # 杂凑运算第二步,对输入的明文进行杂凑运算
        rv = dll.FM_CPC_SM3Update(hDev, au8data, u32InLen)
        if rv != 0:
            print("FM_CPC_SM3Update error! rv=%08x" % rv)
            return str(rv)
        if bOver:
            break

    # 创建数据缓冲区,存放输出的杂凑数据
    au8endata = create_string_buffer(32)
    u32OutLen = c_uint(32)

    # 杂凑运算第三步,运算结束返回杂凑结果数据
    rv = dll.FM_CPC_SM3Final(hDev, au8endata, byref(u32OutLen))
    if rv != 0:
        print("FM_CPC_SM3Final error! rv=%08x" % rv)
        return str(rv)
    s64 = base64.b64encode(au8endata)

    return s64.decode("utf-8")

def doSM3Mac(indata):
    pass


FM_HKEY_TO_HOST = 0x01ffffff  # /* key is not storage in dev */
FM_HKEY_FROM_HOST = 0x02ffffff  # /* use host import temp key */

FM_ALG_SCB2_S = 0x00000001  # /* SCB2 special */
FM_ALG_SCB2_G = 0x00000002  # /* SCB2 general */
FM_ALG_SM1 = FM_ALG_SCB2_G
FM_ALG_SM6 = FM_ALG_SCB2_S
FM_ALG_3DES = 0x00000003
FM_ALG_AES = 0x00000004
FM_ALG_DES = 0x00000005
FM_ALG_RC2 = 0x00000006
FM_ALG_RC4 = 0x00000007
FM_ALG_SM4 = 0x00000008

FM_ALGMODE_ECB = 0x00000000
FM_ALGMODE_CBC = 0x00000001


def getKeylen(uiAlgID):
    algLen = 0
    if uiAlgID == FM_ALG_SM1:
        algLen = 16
    elif uiAlgID == FM_ALG_SM4:
        algLen = 16
    elif uiAlgID == FM_ALG_AES:
        algLen = 16
    elif uiAlgID == FM_ALG_DES:
        algLen = 8
    elif uiAlgID == FM_ALG_3DES:
        algLen = 8

    return algLen


def doEncode(indata, keyID=2):
    hkey = c_void_p(keyID)
    # 使用SM4算法
    u32Alg = c_uint(FM_ALG_SM4)
    # 使用ECB模式
    u32WorkModule = c_uint(FM_ALGMODE_ECB)
    algLen = getKeylen(FM_ALG_SM4)
    if algLen <= 0:
        print('错误的ALG！')
        return "-1"
    b_string = indata.encode("utf-8")
    inLen = len(b_string)
    if inLen > (56 * 1024):
        print('数据过长！')
        return "-1"
    pad = algLen - inLen % algLen
    for xxx in range(0, pad):
        b_string += pad.to_bytes(1, 'big')
    inLen = len(b_string)
    au8data = create_string_buffer(b_string)
    u32InLen = c_uint(inLen)

    au8endata = create_string_buffer(u32InLen.value)
    u32OutLen = c_uint(u32InLen.value)

    rv = dll.FM_CPC_Encrypt(hDev, hkey, u32Alg, u32WorkModule, au8data, u32InLen, au8endata, byref(u32OutLen),
                            None, 0, None, 0)
    if rv != 0:
        print("FM_CPC_Encrypt error! rv=%08x" % rv)
        return str(rv)
    # s = ''
    # for xxx in range(0, u32OutLen.value):
    #     s += str(hex(au8endata.raw[xxx])) + ' '
    # print('加密后数据长度%d：' % u32OutLen.value)
    # print(s)
    s64 = base64.b64encode(au8endata)
    return s64.decode("utf-8")


def doDecode(indata, keyID=2):
    hkey = c_void_p(keyID)
    # 使用SM4算法
    u32Alg = c_uint(FM_ALG_SM4)
    # 使用ECB模式
    u32WorkModule = c_uint(FM_ALGMODE_ECB)

    b_string = indata.encode("utf-8")
    s64in = base64.b64decode(b_string)
    u32InLen = c_uint(len(s64in))

    au8Outata = create_string_buffer(u32InLen.value)
    rv = dll.FM_CPC_Decrypt(hDev, hkey, u32Alg, u32WorkModule, s64in, u32InLen, au8Outata, byref(u32InLen),
                            None, 0, None, 0)
    if rv != 0:
        print("FM_CPC_Decrypt error! rv=%08x" % rv)
        return ""

    pad = au8Outata.raw[u32InLen.value - 1]
    getString = au8Outata.value.decode("utf-8")[:-pad]

    return getString


if __name__ == '__main__':
    print("hello")
    ret = openDevice()
    if ret != 0:
        print("打开设备失败！")
        exit(0)

    # 进行SM3 运算
    strsm3 = "1234567890"
    try:
        sm3ret = doSM3(strsm3)
        if len(sm3ret) < 16:
            print("SM3 异常")
            exit(0)
        print("SM3后数据：%s" % sm3ret)
    except Exception:
        pass
    finally:
        closeDevice()

    stringIn = "你好！"
    encData = doEncode(stringIn)
    if len(encData) < 16:
        print("加密 异常 ")
        exit(0)
    print("加密后数据：%s" % encData)

    decData = doDecode(encData)
    if decData == "":
        print("解密 异常 ")
        exit(0)
    print("解密后数据：%s" % decData)

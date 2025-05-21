import base64
import hashlib
import random
import string
import sys
import time
import uuid

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

import setting


def md5(text: str) -> str:
    """
    计算输入文本的 MD5 哈希值。

    :param text: 输入的文本字符串。
    :return: 输入文本的 MD5 哈希值，以十六进制字符串表示。
    """
    _md5 = hashlib.md5()
    _md5.update(text.encode())
    return _md5.hexdigest()


# 随机文本
def random_text(num: int) -> str:
    """
    生成指定长度的随机文本。

    :param num: 随机文本的长度。
    :return: 生成的随机文本。
    """
    return ''.join(random.sample(string.ascii_lowercase + string.digits, num))


def timestamp() -> int:
    """
    获取当前时间戳。

    :return: 当前时间戳。
    """
    return int(time.time())


def get_ds(web: bool) -> str:
    """
    获取米游社的签名字符串，用于访问米游社API时的签名验证。

    :param web: 是否为网页端请求。如果为 True，则使用手机网页端的 salt；如果为 False，则使用移动端的 salt。
    :return: 返回一个字符串，格式为"时间戳,随机字符串,签名"。
    """
    salt = setting.mihoyobbs_salt
    if web:
        salt = setting.mihoyobbs_salt_web
    i = str(timestamp())
    r = getStr()
    c = md5(f'salt={salt}&t={i}&r={r}')
    return f"{i},{r},{c}"


def get_ds2(query: str = "", body: str = "") -> str:
    """
    获取米游社的签名字符串，用于访问米游社API时的签名验证。

    :param query: 请求的查询参数
    :param body: 请求的主体内容
    :return: 返回一个字符串，格式为"时间戳,随机字符串,签名"。
    """
    salt = setting.mihoyobbs_salt_x6
    i = str(timestamp())
    r = getStr()
    c = md5(f'salt={salt}&t={i}&r={r}&b={body}&q={query}')
    return f"{i},{r},{c}"


def get_device_id(cookie: str) -> str:
    """
    使用 cookie 通过 uuid v3 生成设备 ID。
    :param cookie: cookie

    :return: 设备 ID。
    """
    return str(uuid.uuid3(uuid.NAMESPACE_URL, cookie))


def get_item(raw_data: dict) -> str:
    """
    获取签到的奖励信息

    :param raw_data: 签到的奖励数据
    :return: 「签奖励名称」x数量
    """
    temp_name = raw_data["name"]
    temp_cnt = raw_data["cnt"]
    return f"「{temp_name}」x{temp_cnt}"


def get_next_day_timestamp() -> int:
    """
    获取明天凌晨的时间戳。

    :return: 明天凌晨的时间戳
    """
    now_time = int(time.time())
    next_day_time = now_time - now_time % 86400 + time.timezone + 86400
    return next_day_time


def time_conversion(minute: int) -> str:
    """
    将分钟转换为小时和分钟
    :param minute: 分钟
    :return: 小时和分钟
    """
    h = minute // 60
    s = minute % 60
    return f"{h} 小时 {s} 分钟"


def tidy_cookie(cookies: str) -> str:
    """
    整理cookie
    :param cookies: cookie
    :return: 整理后的cookie
    """
    cookie_dict = {}
    spilt_cookie = cookies.split(";")
    if len(spilt_cookie) < 2:
        return cookies
    for cookie in spilt_cookie:
        cookie = cookie.strip()
        if cookie == "":
            continue
        key, value = cookie.split("=", 1)
        cookie_dict[key] = value
    return "; ".join([f"{key}={value}" for key, value in cookie_dict.items()])


# 获取ua 防止出现多个miHoYoBBS
def get_useragent(useragent: str) -> str:
    if useragent == "":  # 没设置自定义ua就返回默认ua
        return setting.headers['User-Agent']
    if "miHoYoBBS" in useragent:  # 防止出现多个miHoYoBBS
        i = useragent.index("miHoYoBBS")
        if useragent[i - 1] == " ":
            i = i - 1
        return f'{useragent[:i]} miHoYoBBS/{setting.mihoyobbs_version}'
    return f'{useragent} miHoYoBBS/{setting.mihoyobbs_version}'


def get_openssl_version() -> int:
    """
    获取openssl版本号
    :return: OpenSSL 的版本号。
    """
    try:
        import ssl
    except ImportError:
        sys.exit("Openssl Lib Error !!")
        # return -99
        # 建议直接更新Python的版本，有特殊情况请提交issues
    temp_list = ssl.OPENSSL_VERSION_INFO
    return int(f"{str(temp_list[0])}{str(temp_list[1])}{str(temp_list[2])}")


def RSA_encryption(text: str, public_key: bytes):
    # 字符串指定编码（转为bytes）
    text = text.encode('utf-8')
    # 构建公钥对象
    cipher_public = PKCS1_v1_5.new(RSA.importKey(public_key))
    # 加密（bytes）
    text_encrypted = cipher_public.encrypt(text)
    # base64编码，并转为字符串
    text_encrypted_base64 = base64.b64encode(text_encrypted).decode()
    return text_encrypted_base64


def numberOfLeadingZeros(i):
    if i <= 0:
        return 32 if i == 0 else 0
    n = 31
    if i >= 1 << 16:
        n -= 16
        # i = i >>> 16
        i = unsigned_right_shift(i, 16)
    if i >= 1 << 8:
        n -= 8
        # i >>>= 8
        i = unsigned_right_shift(i, 8)
    if i >= 1 << 4:
        n -= 4
        # i >>>= 4
        i = unsigned_right_shift(i, 4)
    if i >= 1 << 2:
        n -= 2
        # i >>>= 2
        i = unsigned_right_shift(i, 2)
    return n - unsigned_right_shift(i, 1)


def unsigned_right_shift(num, shift, bits=32):
    # 将数值转换为无符号形式后右移
    return (num % (1 << bits)) >> shift


def n(paramInt1, paramInt2):
    i = paramInt2 - paramInt1
    if i <= 0 and i != -0x80000000:
        t = 0
        while i == 0 or t == 0:
            j = 32
            k = 0
            i = k
            if paramInt1 <= j:
                i = k
                if j < paramInt2:
                    i = 1
            t = 1
        return j
    if (-i & i) == i:
        paramInt2 = 31 - numberOfLeadingZeros(i)
    else:
        t = 0
        while t == 0 or k - paramInt2 + (i - 1) < 0:
            k = unsigned_right_shift(32, 1)
            paramInt2 = k % i
            t = 1
    return paramInt1 + paramInt2


def getStr():
    randomRange = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    Str = ""
    for i in range(6):
        Str += str(randomRange[n(0, len(randomRange))])
    return Str

import hashlib
import json
import time

import requests

import config
import setting
import tools
from error import StokenError, CookieError
from loghelper import log

public_key = (b"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDvekdPMHN3AYhm/vktJT+YJr7"
              b"\ncI5DcsNKqdsx5DZX0gDuWFuIjzdwButrIYPNmRJ1G8ybDIF7oDW2eEpm5sMbL9zs"
              b"\n9ExXCdvqrn51qELbqj0XxtMTIpaCHFSI50PfPpTFV9Xt/hmyVwokoOXFlAEgCn+Q\nCgGs52bFoYMtyi+xEQIDAQAB\n"
              b"-----END PUBLIC KEY-----")


def getFP():
    getFP_URL = "https://public-data-api.mihoyo.com/device-fp/api/getFp"
    FP_data = ("{\"device_id\":\"8045ba4d5625133c\",\"seed_id\":\"8ccc059c-c12e-4e50-a293-e663e041f529\","
               "\"seed_time\":\"1720537893088\",\"platform\":\"2\",\"device_fp\":\"38d7fc24903c4\","
               "\"app_name\":\"bbs_cn\",\"ext_fields\":\"{\\\"appInstallTimeDiff\\\":1720537884840,"
               "\\\"chargeStatus\\\":1,\\\"appUpdateTimeDiff\\\":1720537884840,\\\"debugStatus\\\":0,"
               "\\\"isRoot\\\":0,\\\"buildTime\\\":\\\"1682413330000\\\",\\\"oaid\\\":\\\"error_1002005\\\","
               "\\\"batteryStatus\\\":96,\\\"sdkVersion\\\":\\\"25\\\",\\\"serialNumber\\\":\\\"002e9071\\\","
               "\\\"vaid\\\":\\\"error_1002005\\\",\\\"manufacturer\\\":\\\"Xiaomi\\\",\\\"simState\\\":5,"
               "\\\"screenSize\\\":\\\"900x1600\\\",\\\"isMockLocation\\\":0,\\\"deviceName\\\":\\\"Mi 10\\\","
               "\\\"sdRemain\\\":14701,\\\"proxyStatus\\\":0,\\\"networkType\\\":\\\"WiFi\\\","
               "\\\"aaid\\\":\\\"error_1002005\\\",\\\"packageVersion\\\":\\\"2.16.0\\\","
               "\\\"magnetometer\\\":\\\"-38.935x0.01x-0.035\\\",\\\"display\\\":\\\"N2G48C\\\","
               "\\\"emulatorStatus\\\":0,\\\"productName\\\":\\\"Mi 10\\\",\\\"ramRemain\\\":\\\"14697\\\","
               "\\\"isTablet\\\":1,\\\"vendor\\\":\\\"中国移动\\\",\\\"devId\\\":\\\"REL\\\",\\\"sdCapacity\\\":15998,"
               "\\\"packageName\\\":\\\"com.mihoyo.hyperion\\\",\\\"hostname\\\":\\\"ubuntu\\\","
               "\\\"romCapacity\\\":\\\"256\\\",\\\"osVersion\\\":\\\"7.1.2\\\",\\\"ramCapacity\\\":\\\"15998\\\","
               "\\\"buildType\\\":\\\"user\\\",\\\"isAirMode\\\":0,\\\"hasKeyboard\\\":1,"
               "\\\"accelerometer\\\":\\\"0.049999997x9.670001x2.0397706\\\",\\\"deviceType\\\":\\\"aosp\\\","
               "\\\"ringMode\\\":2,\\\"cpuType\\\":\\\"armeabi-v7a\\\",\\\"board\\\":\\\"Mi 10\\\","
               "\\\"romRemain\\\":\\\"239\\\",\\\"appMemory\\\":\\\"256\\\",\\\"buildUser\\\":\\\"build\\\","
               "\\\"brand\\\":\\\"Xiaomi\\\",\\\"buildTags\\\":\\\"release-keys\\\","
               "\\\"ui_mode\\\":\\\"UI_MODE_TYPE_NORMAL\\\","
               "\\\"deviceInfo\\\":\\\"google\\\\\\/android_x86\\\\\\/x86:7.1.2\\\\\\/N2G48C\\\\\\/4565141:user"
               "\\\\\\/release-keys\\\",\\\"hardware\\\":\\\"android_x86\\\","
               "\\\"gyroscope\\\":\\\"0.0x0.0x3.0E-4\\\",\\\"model\\\":\\\"Mi 10\\\"}\","
               "\"bbs_device_id\":\"7e219ba9-24a9-3ef8-87eb-02c83e7217b5\"}")
    r = requests.post(getFP_URL, data=FP_data, headers={'Content-Type': 'application/json',
                                                        'Accept': 'application/json;charset=utf-8'})
    fp = json.loads(r.content.decode(encoding='utf-8'))['data']['device_fp']
    return fp


def login_bbs(account, password):
    loginJson = {"account": tools.RSA_encryption(account, public_key),
                 "password": tools.RSA_encryption(password, public_key)}
    headers = {"x-rpc-app_id": setting.mihoyobbs_verify_key,
               "x-rpc-client_type": setting.mihoyobbs_Client_type,
               "x-rpc-device_id": "8045ba4d5625133c",
               "x-rpc-device_fp": getFP(),
               "x-rpc-device_name": "Mi+10",
               "x-rpc-game_biz": "bbs_cn",
               "x-rpc-sdk_version": "2.16.1",
               "x-rpc-app_version": setting.mihoyobbs_version,
               "DS": tools.get_ds2("", json.dumps(loginJson))}
    r = requests.post(setting.bbs_login_url, data=json.dumps(loginJson), headers=headers)
    resp = json.loads(r.content.decode(encoding='utf-8'))
    if resp['retcode'] == 0:
        try:
            stoken = resp['data']['token']['token']
        except KeyError:
            stoken = ""
            log.error("BBS登录成功，但未包含SToken，请手动获取")
            raise StokenError("SToken自动获取失败")
    else:
        stoken = ""
        log.error("BBS登录失败，请手动获取SToken")
        raise StokenError("SToken自动获取失败")
    # config.load_config()
    config.config["account"]["stoken"] = stoken
    config.config["account"]["stuid"] = resp['data']['user_info']['aid']
    config.config["account"]["mid"] = resp['data']['user_info']['mid']
    # config.save_config()


def login_bbs_web(account, password):
    headers = {"host": "passport-api.miyoushe.com",
               "origin": "https://user.miyoushe.com",
               "pragma": "no-cache",
               "referer": "https://user.miyoushe.com/",
               "sec-ch-ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
               "sec-ch-ua-mobile": "?0",
               "sec-ch-ua-platform": '"Windows"',
               "sec-fetch-dest": 'empty',
               "sec-fetch-mode": "cors",
               "sec-fetch-site": "same-site",
               "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                             "Chrome/136.0.0.0 Safari/537.36",
               "x-rpc-app_id": setting.mihoyobbs_verify_key,
               "x-rpc-client_type": "4",
               "x-rpc-device_fp": "38d80b6f56c70",
               "x-rpc-device_id": "b1fcc49a-8665-4184-836b-f8583ca64794",
               "x-rpc-device_model": "Chrome%20136.0.0.0",
               "x-rpc-device_name": "Chrome",
               "x-rpc-device_os": "Windows%2010%2064-bit",
               "x-rpc-game_biz": "bbs_cn",
               "x-rpc-lifecycle_id": "26e5875ee0",
               "x-rpc-mi_referrer": "https://user.miyoushe.com/login-platform/index.html?app_id=bll8iq97cem8&theme"
                                    "=&token_type=4&game_biz=bbs_cn&message_origin=https%253A%252F%252Fwww.miyoushe"
                                    ".com&succ_back_type=message%253Alogin-platform%253Alogin-success&fail_back_type"
                                    "=message%253Alogin-platform%253Alogin-fail&ux_mode=popup&iframe_level=1#/login"
                                    "/password",
               "x-rpc-sdk_version": "2.39.0",
               "x-rpc-source": "v2.webLogin"}
    account_enc = tools.RSA_encryption(account, public_key)
    password_enc = tools.RSA_encryption(password, public_key)
    r = requests.post(setting.bbs_login_web_url, json={'account': account_enc, 'password': password_enc},
                      headers=headers)
    if json.loads(r.content.decode(encoding='utf-8'))["retcode"] != 0:
        log.error(f"自动登录出现异常！MSG：{json.loads(r.content.decode(encoding='utf-8'))['message']}")
        raise CookieError("Cookie自动获取失败")
    cookie = ""
    for k, v in r.cookies.items():
        cookie += f"{k}={v};"
    print(cookie)
    # config.load_config()
    config.config["account"]["cookie"] = f"{cookie}"
    # config.save_config()


def login_verify():
    cookie = f"stoken={config.config['account']['stoken']};mid={config.config['account']['mid']};"
    headers = {"x-rpc-app_id": setting.mihoyobbs_verify_key,
               "x-rpc-client_type": setting.mihoyobbs_Client_type,
               "x-rpc-device_id": "8045ba4d5625133c",
               "x-rpc-device_fp": getFP(),
               "x-rpc-device_name": "Mi+10",
               "x-rpc-game_biz": "bbs_cn",
               "x-rpc-sdk_version": "2.16.1",
               "x-rpc-app_version": setting.mihoyobbs_version,
               "DS": tools.get_ds(False),
               "cookie": cookie}
    r = requests.get(setting.bbs_login_verify, headers=headers)
    resp = json.loads(r.content.decode(encoding='utf-8'))
    if resp['retcode'] == 0:
        return True, ""
    else:
        return False, resp['message']


def login_verify_web():
    headers = {"accept": "application/json, text/plain, */*",
               "accept-encoding": "gzip, deflate, br, zstd",
               "accept-language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
               "cache-control": "no-cache",
               "cookie": config.config['account']['cookie'],
               "origin": "https://www.miyoushe.com",
               "referer": "https://www.miyoushe.com/",
               "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                             "Chrome/136.0.0.0 Safari/537.36",
               "x-rpc-app_version": "2.87.0",
               "x-rpc-client_type": "4",
               "x-rpc-device_fp": "38d80b6f793c0",
               "x-rpc-device_id": "b1fcc49a-8665-4184-836b-f8583ca64794"
               }
    r = requests.get(setting.bbs_login_verify_web, headers=headers)
    resp = json.loads(r.content.decode(encoding='utf-8'))
    if resp['retcode'] == 0:
        return True, ""
    else:
        return False, resp['message']


# if __name__ == "__main__":
#     login_bbs()

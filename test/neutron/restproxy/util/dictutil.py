# coding:utf-8
# coding:utf-8

#
# 判断dict是否为空
#


def isNotEmpty(dict):
    if dict:
        return True

    return False

#
# 扩展目标的dict对象
#


def extend(destDict, srcDict):

    for i in srcDict:
        destDict[i] = srcDict[i]

from functools import reduce
import numpy as np
import pandas as pd


def readGhidra(filename):
    """Return a dataframe from the preprocessed Ghidra output"""

    column_names = ["File", "Func", "Param", "FuncAddr", "Addr", "Value", "Rep"]
    df = pd.read_csv(filename, sep=" ", names=column_names)
    return df


def getParam(funcName):
    """Return function parameters"""

    signatures = {
        "open": ["__file", "__oflag"],
        "fopen": ["__filename", "__modes"],
        "inet_aton": ["__cp", "__inp"],
        "inet_addr": ["__cp"],
        "mkfifo": ["__path", "__mode"],
        "popen": ["__command", "__modes"],
        "system": ["__command"],
        "execv": ["__path", "__argv"],
        "execve": ["__path", "__argv"],
        "execl": ["__path", "__arg"],
        "execle": ["__path", "__arg"],
        "execlp": ["__file", "__arg"],
        "execvp": ["__argv"],
    }
    if funcName in signatures:
        return signatures[funcName]
    return None


def getPartialCall(df, funcName):
    """Returns partial function calls, i.e. one entry per argument and call"""

    params = getParam(funcName)
    if params == None:
        return None
    part_call = df.loc[df["Func"] == funcName]
    return part_call


def getCompleteCall(df, funcName):
    """Returns the recovered complete calls, i.e. one entry per call with all arguments. May loose data due to partial argument loss in Ghidra analysis."""

    params = getParam(funcName)
    if params == None:
        return None
    func_df = df.loc[df["Func"] == funcName]
    func_df = func_df[["File", "Func", "FuncAddr", "Param", "Value", "Rep"]]
    if len(params) == 1:
        return func_df

    arg_dfs = []
    for param in params:
        arg_dfs.append(func_df.loc[func_df["Param"] == param])
    call = reduce(lambda left, right: merger(left, right), arg_dfs)
    return call


def merger(arg_df1, arg_df2):
    """Returns the inner joined function calls"""

    return pd.merge(arg_df1, arg_df2, on=["File", "Func", "FuncAddr"], how="inner")


def getSummaryPartial(part_call):
    """Returns the grouped calls by binary, function and argument."""

    return (
        part_call.groupby(["File", "Func", "Rep"])
        .size()
        .reset_index()
        .rename(columns={0: "count"})
    )


def getSummary(calls, funcName):
    """Returns the grouped calls by binary, function and argument."""

    groupers = ["File", "Func"]
    if funcName == "open":
        groupers.append("Rep_x")
        groupers.append("Value_y")

    elif funcName == "inet_aton":
        groupers.append("Rep_x")
        groupers.append("Value_y")

    elif funcName == "mkfifo":
        groupers.append("Rep_x")
        groupers.append("Value_y")

    elif funcName in ["execvp", "inet_addr", "system"]:
        groupers.append("Rep")

    elif funcName in ["popen", "fopen", "execlp", "execl", "execle", "execv", "execve"]:
        groupers.append("Rep_x")
        groupers.append("Rep_y")

    summary = calls.groupby(groupers).size().reset_index(name="Frequency")
    return summary

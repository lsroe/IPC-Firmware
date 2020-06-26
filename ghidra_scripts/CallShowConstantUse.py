# Script will iterate over relevant functions and their parameters
# and call the ShowConstantUseHeadless script

from ghidra.program.util import VariableLocFieldLocation


funcs = [
    "open",
    "fopen",
    "mkfifo",
    "mq_open",
    "shm_open",
    "shmat",
    "sem_open",
    "ftok",
    "inet_aton",
    "inet_addr",
    "inet_network",
    "htons",
    "gethostbyname",
    "execl",
    "execlp",
    "execle",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "popen",
    "system"
]

functionManager = currentProgram.getFunctionManager()
progName = "Program: " + currentProgram.getName()
it = functionManager.getFunctions(True)

while it.hasNext():
    inst = it.next()
    if inst.getName() not in funcs:
        continue
    funName = "Funtion: " + inst.getName()

    for param in inst.getParameters():
        paramName = "Parameter: " + param.getName()
        print progName + "  " + funName + "  " + paramName
        loc = VariableLocFieldLocation(currentProgram, inst.getEntryPoint(), param, 0)
        currentLocation = loc
        state.addEnvironmentVar("Loc", loc)
        state.addEnvironmentVar("FunName", inst.getName())
        state.addEnvironmentVar("FunParam", param.getName())
        runScript("ShowConstantUseHeadless.java", state)

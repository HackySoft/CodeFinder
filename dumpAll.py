from ghidra.app.script import GhidraScript
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
print("starting decompiler by kujoun")
decompiler = DecompInterface()
decompiler.openProgram(currentProgram())
functionManager = currentProgram().getFunctionManager()
output_directory = r"/decomp/allFuncs.txt"
functions = list(functionManager.getFunctions(True))
total_functions = len(functions)
print("number of functions to decompile")
print(total_functions)
with open(output_directory, "w") as result_file:
    for idx, func in enumerate(functions):
        decompilation = decompiler.decompileFunction(func, 60, ConsoleTaskMonitor())
        if decompilation.decompileCompleted():
            decompiled_code = decompilation.getDecompiledFunction().getC()
            result_file.write(decompiled_code)
            progress = (idx + 1) / total_functions * 100
            print(round(progress*100)/100)

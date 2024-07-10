# @category CodeTools
# @menupath Tools.Ghidra CodeTools.runTools
import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog
import json
from ghidra.app.script import GhidraScript
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.address import Address
import re
import os

# Initialize the decompiler
decompiler = DecompInterface()
decompiler.openProgram(currentProgram())
functionManager = currentProgram().getFunctionManager()
class InstructionEditor:
    def __init__(self, master):
        self.master = master
        self.master.title("Instruction Editor")
        self.log_dataa = ""
        self.instructions = []

        self.create_menu()

        self.main_frame = tk.Frame(master)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.listbox = tk.Listbox(self.main_frame)
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.scrollbar = tk.Scrollbar(self.main_frame, orient="vertical")
        self.scrollbar.config(command=self.listbox.yview)
        self.scrollbar.pack(side=tk.LEFT, fill="y")

        self.listbox.config(yscrollcommand=self.scrollbar.set)

        self.button_frame = tk.Frame(self.main_frame)
        self.button_frame.pack(side=tk.RIGHT, fill=tk.Y)

        self.add_button = tk.Button(self.button_frame, text="Add", command=self.add_instruction)
        self.add_button.pack(fill=tk.X)

        self.edit_button = tk.Button(self.button_frame, text="Edit", command=self.show_edit_view)
        self.edit_button.pack(fill=tk.X)

        self.delete_button = tk.Button(self.button_frame, text="Delete", command=self.delete_instruction)
        self.delete_button.pack(fill=tk.X)

        self.run_button = tk.Button(self.button_frame, text="Run", command=self.run_instruction)
        self.run_button.pack(fill=tk.X)

        self.edit_frame = tk.Frame(master)

        self.finder1_label = tk.Label(self.edit_frame, text="Finder First String:")
        self.finder1_entry = tk.Entry(self.edit_frame)
        self.finder2_label = tk.Label(self.edit_frame, text="Finder Second String:")
        self.finder2_entry = tk.Entry(self.edit_frame)
        self.regex_string_label = tk.Label(self.edit_frame, text="Regex String:")
        self.regex_string_entry = tk.Entry(self.edit_frame)

        self.regex_list_label = tk.Label(self.edit_frame, text="Regex List:")
        self.regex_listbox = tk.Listbox(self.edit_frame)
        self.regex_scrollbar = tk.Scrollbar(self.edit_frame, orient="vertical")
        self.regex_scrollbar.config(command=self.regex_listbox.yview)
        self.regex_listbox.config(yscrollcommand=self.regex_scrollbar.set)

        self.regex_add_button = tk.Button(self.edit_frame, text="Add Regex Item", command=self.add_regex_item)
        self.regex_edit_button = tk.Button(self.edit_frame, text="Edit Regex Item", command=self.edit_regex_item)
        self.regex_delete_button = tk.Button(self.edit_frame, text="Delete Regex Item", command=self.delete_regex_item)

        self.should_run_label = tk.Label(self.edit_frame, text="Should Run:")
        self.should_run_var = tk.BooleanVar()
        self.should_run_checkbutton = tk.Checkbutton(self.edit_frame, variable=self.should_run_var)

        self.min_size_label = tk.Label(self.edit_frame, text="Min Size:")
        self.min_size_entry = tk.Entry(self.edit_frame)
        self.max_size_label = tk.Label(self.edit_frame, text="Max Size:")
        self.max_size_entry = tk.Entry(self.edit_frame)

        self.save_button = tk.Button(self.edit_frame, text="Save", command=self.save_instruction)
        self.cancel_button = tk.Button(self.edit_frame, text="Cancel", command=self.cancel_edit)

        self.log_frame = tk.Frame(master)
        self.log_text = tk.Text(self.log_frame, height=10, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_frame.pack(fill=tk.BOTH, expand=True)

    def create_menu(self):
        menu = tk.Menu(self.master)
        self.master.config(menu=menu)

        file_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Load", command=self.load_instructions)
        file_menu.add_command(label="Save", command=self.save_instructions)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.master.quit)

    def add_instruction(self):
        instruction = [["", ""], ["", []], [False, 0, 0]]
        self.instructions.append(instruction)
        self.update_listbox()

    def show_edit_view(self):
        selected_index = self.listbox.curselection()
        if not selected_index:
            messagebox.showwarning("Warning", "Select an instruction to edit")
            return

        self.index = selected_index[0]
        instruction = self.instructions[self.index]

        self.finder1_entry.delete(0, tk.END)
        self.finder1_entry.insert(0, instruction[0][0])
        self.finder2_entry.delete(0, tk.END)
        self.finder2_entry.insert(0, instruction[0][1])
        self.regex_string_entry.delete(0, tk.END)
        self.regex_string_entry.insert(0, instruction[1][0])

        self.regex_listbox.delete(0, tk.END)
        for item in instruction[1][1]:
            self.regex_listbox.insert(tk.END, item)

        self.should_run_var.set(instruction[2][0])
        self.min_size_entry.delete(0, tk.END)
        self.min_size_entry.insert(0, instruction[2][1])
        self.max_size_entry.delete(0, tk.END)
        self.max_size_entry.insert(0, instruction[2][2])

        self.main_frame.pack_forget()
        self.log_frame.pack_forget()
        self.edit_frame.pack(fill=tk.BOTH, expand=True)
        self.place_edit_widgets()

    def place_edit_widgets(self):
        self.finder1_label.pack()
        self.finder1_entry.pack()
        self.finder2_label.pack()
        self.finder2_entry.pack()
        self.regex_string_label.pack()
        self.regex_string_entry.pack()

        self.regex_list_label.pack()
        self.regex_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.regex_scrollbar.pack(side=tk.LEFT, fill="y")
        self.regex_add_button.pack()
        self.regex_edit_button.pack()
        self.regex_delete_button.pack()

        self.should_run_label.pack()
        self.should_run_checkbutton.pack()
        self.min_size_label.pack()
        self.min_size_entry.pack()
        self.max_size_label.pack()
        self.max_size_entry.pack()

        self.save_button.pack()
        self.cancel_button.pack()

    def add_regex_item(self):
        new_item = simpledialog.askstring("Input", "Enter a Regex list item:")
        if new_item:
            self.regex_listbox.insert(tk.END, new_item)

    def edit_regex_item(self):
        selected_index = self.regex_listbox.curselection()
        if not selected_index:
            messagebox.showwarning("Warning", "Select a Regex item to edit")
            return

        index = selected_index[0]
        current_value = self.regex_listbox.get(index)
        new_value = simpledialog.askstring("Input", "Edit the Regex list item:", initialvalue=current_value)
        if new_value:
            self.regex_listbox.delete(index)
            self.regex_listbox.insert(index, new_value)

    def delete_regex_item(self):
        selected_index = self.regex_listbox.curselection()
        if not selected_index:
            messagebox.showwarning("Warning", "Select a Regex item to delete")
            return

        index = selected_index[0]
        self.regex_listbox.delete(index)

    def save_instruction(self):
        finder_1 = self.finder1_entry.get()
        finder_2 = self.finder2_entry.get()
        regex_string = self.regex_string_entry.get()

        regex_list = [self.regex_listbox.get(i) for i in range(self.regex_listbox.size())]

        should_run = self.should_run_var.get()
        min_size = int(self.min_size_entry.get())
        max_size = int(self.max_size_entry.get())

        self.instructions[self.index] = [[finder_1, finder_2], [regex_string, regex_list], [should_run, min_size, max_size]]
        self.update_listbox()
        self.cancel_edit()

    def cancel_edit(self):
        self.edit_frame.pack_forget()
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.log_frame.pack(fill=tk.BOTH, expand=True)

    def delete_instruction(self):
        selected_index = self.listbox.curselection()
        if not selected_index:
            messagebox.showwarning("Warning", "Select an instruction to delete")
            return

        index = selected_index[0]
        del self.instructions[index]
        self.update_listbox()

    def run_instruction(self):
        selected_index = self.listbox.curselection()
        if not selected_index:
            messagebox.showwarning("Warning", "Select an instruction to run")
            return

        index = selected_index[0]
        instruction = self.instructions[index]
        entrySymbol = instruction[0][0]
        functionOnly = False
        if '.' in entrySymbol:
            # If the instruction starts with a dot, it implies a file load operation
            # If you want the decomp of the references to the function it should have the FUN_ part
            # If not dont include it and it will decompile only the address
            with open("keys/"+entrySymbol, 'r') as file:
                entrySymbol = file.read()
                functionOnly = entrySymbol.find('FUN_') == -1  
        self.run_instruction_symbol(entrySymbol,instruction[0][1],instruction[1],instruction[2],functionOnly)
    
    def run_instruction_symbol(self,entrySymbol,exitFile,regObj,setObj,functionOnly):
        alreadyDecomp = []
        useSettings = setObj[0]
        min_size = setObj[1]
        max_size = setObj[2]
        print(functionOnly,entrySymbol)
        with open("decomp/"+exitFile, "w") as result_file:
            if functionOnly:
                address = toAddr(entrySymbol)
                func = functionManager.getFunctionAt(address)
                if func is not None:
                    decompilation = decompiler.decompileFunction(func, 60, ConsoleTaskMonitor())
                    if decompilation.decompileCompleted():
                    # Get the decompiled code
                        decompiled_code = decompilation.getDecompiledFunction().getC()
                        result_file.write(decompiled_code)
            else:
                for func in functionManager.getFunctions(True):
                    if func.getName() == entrySymbol:
                            address = func.getEntryPoint()
                            func = functionManager.getFunctionAt(address)
                            if func is not None:
                                allReferences = getReferencesTo(address)
                                for ref in allReferences:
                                    t_func = getFunctionContaining(ref.getFromAddress())
                                    if t_func is not None:
                                        nameOfFunc = t_func.getName()
                                        if nameOfFunc not in alreadyDecomp:
                                            sizeOfFunc = t_func.getBody().getNumAddresses()
                                            if(not useSettings or (sizeOfFunc<max_size and sizeOfFunc>min_size)): 
                                                decompilation = decompiler.decompileFunction(t_func, 60, ConsoleTaskMonitor())
                                                alreadyDecomp.append(nameOfFunc)
                                                if decompilation.decompileCompleted():
                                                # Get the decompiled code
                                                    decompiled_code = decompilation.getDecompiledFunction().getC()
                                                    result_file.write(decompiled_code)
                                                    result_file.write(nameOfFunc)
        self.run_regex(exitFile,regObj)

    def run_regex(self, exitFile, regObj):
        regex_string = regObj[0]
        resultList = regObj[1]
        
        # Compile the regular expression
        regex = f'{regex_string}'
        
        # Open the file and read its contents
        with open("decomp/"+exitFile, 'r') as file:
            file_contents = file.read()
        
        # Find all matches of the regex in the file contents
        matches = re.finditer(regex,file_contents,re.MULTILINE)
        
        # Iterate through matches and write output to respective files
        for match in matches:
            for index, filename in enumerate(resultList):
                with open("keys/"+filename, 'w') as outfile:
                    outfile.write(match.group(index+1))
                    self.log_text.config(state=tk.NORMAL)
                    self.log_text.insert(tk.END, match.group(index+1)+"\n")
                    self.log_text.config(state=tk.DISABLED)

    def update_listbox(self):
        self.listbox.delete(0, tk.END)
        for instruction in self.instructions:
            finder = instruction[0]
            settings = instruction[2]
            display_text = f"Finder: {finder}, Settings: {settings}"
            self.listbox.insert(tk.END, display_text)

    def load_instructions(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if file_path:
            with open(file_path, 'r') as file:
                self.instructions = json.load(file)
            self.update_listbox()

    def save_instructions(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file_path:
            with open(file_path, 'w') as file:
                json.dump(self.instructions, file)

#This is the code that crashes
    root = tk.Tk()
    app = InstructionEditor(root)
    root.mainloop()

# CodeFinder
Code finder using ghidrathon + regex
!!YOU NEED TO INSTALL GHIDRATHON!!
# Important
With our new GUI, we've made some changes to how functions are referenced in text files. Now, whenever we refer to a function from a text file, we need to use a keyword FUN_ followed by the function's full name. For example, if the function's full name is FUN_00a3a5c8, to decompile all references to it we would reference it as FUN_00a3a5c8 in our text files.

If we want to decompile the actual function FUN_00a3a5c8 (without the FUN_ prefix), we save it simply as 00a3a5c8 in our files. This way, FUN_00a3a5c8 is used for references, and 00a3a5c8 is used for the actual function.

If there are any unnecessary matches or groups in the regex results, please place them in a file named "trash.txt".

#Usage

find a native function/debug function, put its name and it will decompile all references to it
afterwards you can run regex on all of them to get whatever function/address you want

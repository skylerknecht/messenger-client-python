import ast
import asyncio
import random
import os
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

class Pyfuscator(ast.NodeTransformer):
    def __init__(self):
        super().__init__()
        self.var_map = {}
        self.func_map = {}
        self.class_map = {}
        self.obfuscate_blacklist = {
            *dir(__builtins__),
            *dir(object),
            *{
                'self',
                'cls'
            },
        }
        self.word_list = [
            "apple", "banana", "cherry", "dragon", "elephant", "falcon", "gorilla", "hippo",
            "iguana", "jaguar", "kangaroo", "lion", "monkey", "narwhal", "octopus", "panda",
            "quokka", "rhinoceros", "squirrel", "tiger", "umbrella", "vulture", "walrus", "xenops",
            "yak", "zebra"
        ]

    def _random_variable_name(self):
        """Generates a random PEP 8-compliant variable name in snake_case."""
        return f"{random.choice(self.word_list)}_{random.choice(self.word_list)}"

    def _random_class_name(self):
        """Generates a random PEP 8-compliant class name in PascalCase."""

        def capitalize(word):
            return word.capitalize()

        return capitalize(random.choice(self.word_list)) + capitalize(random.choice(self.word_list))

    def visit_Import(self, node):
        """ Track imported modules to prevent obfuscation. """
        for alias in node.names:
            self.obfuscate_blacklist.add(alias.name.split('.')[0])
        return node

    def visit_ImportFrom(self, node):
        """ Track module from which functions/classes are imported. """
        if node.module:
            self.obfuscate_blacklist.add(node.module.split('.')[0])
        return node

    def visit_Assign(self, node):
        """
        Processes assignment (`=`) statements in the AST to obfuscate variable names while ensuring attributes (`obj.value`)
        and subscripts (`arr[0]`) are not affected.

        Why We Do This:
        -----------------
        The AST represents assignments as `Assign` nodes. The `targets` attribute holds the variables being assigned.
        We obfuscate only **Name** nodes (variables) and **skip attributes and subscripts**, as those should remain unchanged.

        Example 1: Simple Variable Assignment (Obfuscate `x`)
        --------------------------------------------------------
        Python Code:
            x = 10

        AST Representation:
            Assign(
                targets=[Name(id='x', ctx=Store())],  # `x` is a variable name → should be obfuscated
                value=Constant(value=10)
            )

        Transformation:
            `_xyz123 = 10` (obfuscated variable name)

        --------------------------------------------------------

        Example 2: Attribute Assignment (Do NOT obfuscate `obj.value`)
        -----------------------------------------------------------------
        Python Code:
            obj.value = 10

        AST Representation:
            Assign(
                targets=[Attribute(
                    value=Name(id='obj', ctx=Load()),  # `obj` can be obfuscated
                    attr='value', ctx=Store()  # `value` should NOT be obfuscated
                )],
                value=Constant(value=10)
            )

        Why?
            - `obj` is a user-defined variable and can be obfuscated.
            - `.value` is a property of `obj` and should NOT be renamed.

        --------------------------------------------------------

        Example 3: List Indexing (Do NOT obfuscate `arr[0]`)
        --------------------------------------------------------
        Python Code:
            arr[0] = 42

        AST Representation:
            Assign(
                targets=[Subscript(
                    value=Name(id='arr', ctx=Load()),  # `arr` can be obfuscated
                    slice=Constant(value=0),  # `[0]` should NOT be changed
                    ctx=Store()
                )],
                value=Constant(value=42)
            )

        Why?
            - `arr` is a user-defined variable and should be obfuscated.
            - `[0]` refers to an index and should NOT be changed.

        Implementation:
        -----------------
        - `self.generic_visit(node)`: First, visit all child nodes to ensure any inner variables get processed.
        - Iterate over `node.targets` (left-hand side of `=`).
        - Check if `target` is an `ast.Name` (a variable).
        - If `target` is a variable and hasn't been obfuscated yet, rename it.
        - Return the modified `Assign` node.
        """
        self.generic_visit(node)  # Process child nodes first

        # Rename variable assignments
        for target in node.targets:
            if isinstance(target, ast.Name):  # Ensure it's a variable (not an attribute or subscript)
                if target.id in self.var_map.values() or target.id in self.obfuscate_blacklist:
                    continue
                if target.id not in self.var_map:
                    self.var_map[target.id] = self._random_variable_name()
                target.id = self.var_map[target.id]

        return node

    def visit_ClassDef(self, node):
        if node.name not in self.class_map:
            self.class_map[node.name] = self._random_class_name()
        node.name = self.class_map[node.name]
        self.generic_visit(node)
        return node

    def visit_FunctionDef(self, node):
        if node.name not in self.obfuscate_blacklist:
            if node.name not in self.func_map:
                self.func_map[node.name] = self._random_variable_name()
            node.name = self.func_map[node.name]

        # Rename function arguments
        for arg in node.args.args:
            if arg.arg in self.obfuscate_blacklist:
                continue
            if arg.arg not in self.var_map:
                self.var_map[arg.arg] = self._random_variable_name()
            arg.arg = self.var_map[arg.arg]  # Rename the argument

        node = self.generic_visit(node)  # Process the function body
        return node

    def visit_AsyncFunctionDef(self, node):
        if node.name not in self.obfuscate_blacklist:
            if node.name not in self.func_map:
                self.func_map[node.name] = self._random_variable_name()
            node.name = self.func_map[node.name]

        # Rename function arguments
        for arg in node.args.args:
            if arg.arg in self.obfuscate_blacklist:
                continue
            if arg.arg not in self.var_map:
                self.var_map[arg.arg] = self._random_variable_name()
            arg.arg = self.var_map[arg.arg]  # Rename the argument

        node = self.generic_visit(node)  # Process the function body
        return node

    def visit_Constant(self, node):
        """ Obfuscate string and byte constants. """
        if isinstance(node.value, str):
            return self._encode_string(node.value, node)
        elif isinstance(node.value, bytes):
            return node
        return node

    def visit_JoinedStr(self, node):
        """ Obfuscate f-strings while keeping dynamic expressions intact. """
        new_values = []
        for part in node.values:
            if isinstance(part, ast.Str):
                new_values.append(self._encode_string(part.s, part))
            elif isinstance(part, ast.FormattedValue):
                new_values.append(
                    ast.Call(
                        func=ast.Name(id="str", ctx=ast.Load()),
                        args=[self.visit(part.value)],
                        keywords=[]
                    )
                )
            else:
                new_values.append(part)

        return ast.copy_location(
            ast.Call(
                func=ast.Attribute(value=ast.Constant(value=""), attr="join", ctx=ast.Load()),
                args=[ast.List(elts=new_values, ctx=ast.Load())],
                keywords=[]
            ),
            node
        )

    def _encode_string(self, value, node):
        """ Obfuscate string constants using modular arithmetic encoding. """
        chars, offsets = [], []
        for c in value:
            offset = random.randint(1, 50)
            chars.append(ast.Constant(value=(ord(c) + offset) % 128))
            offsets.append(ast.Constant(value=offset))

        new_node = ast.Call(
            func=ast.Attribute(value=ast.Constant(value=""), attr="join", ctx=ast.Load()),
            args=[
                ast.GeneratorExp(
                    elt=ast.Call(
                        func=ast.Name(id="chr", ctx=ast.Load()),
                        args=[
                            ast.BinOp(
                                left=ast.BinOp(left=ast.Name(id="x", ctx=ast.Load()), op=ast.Sub(),
                                               right=ast.Name(id="y", ctx=ast.Load())),
                                op=ast.Mod(),
                                right=ast.Constant(value=128)
                            )
                        ],
                        keywords=[]
                    ),
                    generators=[
                        ast.comprehension(
                            target=ast.Tuple(
                                elts=[ast.Name(id="x", ctx=ast.Store()), ast.Name(id="y", ctx=ast.Store())],
                                ctx=ast.Store()),
                            iter=ast.Call(func=ast.Name(id="zip", ctx=ast.Load()),
                                          args=[ast.List(elts=chars, ctx=ast.Load()),
                                                ast.List(elts=offsets, ctx=ast.Load())], keywords=[]),
                            ifs=[],
                            is_async=0
                        )
                    ]
                )
            ],
            keywords=[]
        )
        return ast.copy_location(new_node, node)

    def obfuscate_python_file(self, client, output):
        tree = ast.parse(client)

        self.visit(tree)
        obfuscated_tree = New(self.obfuscate_blacklist, self.var_map, self.func_map, self.class_map).visit(tree)
        obfuscated_code = ast.unparse(obfuscated_tree)

        new_file_path = output if output.endswith('.py') else output + '.py'
        with open(new_file_path, 'w', encoding='utf-8') as f:
            f.write(obfuscated_code)
        print(f"[+] Saved python client as {new_file_path}")

class New(ast.NodeTransformer):
    def __init__(self, blacklist, var_map, func_map, class_map):
        super().__init__()
        self.var_map = var_map
        self.func_map = func_map
        self.class_map = class_map
        self.obfuscate_blacklist = {
            *dir(__builtins__),
            *dir(object),
            *{
                'self',
                'cls'
            },
            *blacklist
        }
        self.word_list = [
            "apple", "banana", "cherry", "dragon", "elephant", "falcon", "gorilla", "hippo",
            "iguana", "jaguar", "kangaroo", "lion", "monkey", "narwhal", "octopus", "panda",
            "quokka", "rhinoceros", "squirrel", "tiger", "umbrella", "vulture", "walrus", "xenops",
            "yak", "zebra"
        ]

    def visit_Name(self, node):
        # Merge all mappings into one lookup dictionary
        obfuscation_map = {**self.var_map, **self.func_map, **self.class_map}

        # Replace the name if it has been obfuscated
        if node.id in obfuscation_map:
            node.id = obfuscation_map[node.id]

        return node

    def visit_Attribute(self, node: ast.Attribute):
        # 1) recurse into the value side so nested Names / Attributes get handled
        node.value = self.visit(node.value)

        # 2) find the root of the chain: foo.bar.baz → foo
        root = node
        while isinstance(root, ast.Attribute):
            root = root.value

        # 3) if the root is a Name and we never collected it, skip renaming
        if isinstance(root, ast.Name):
            if root.id not in self.obfuscate_blacklist:
                return node

        # 4) otherwise merge your maps and rename the attr if needed
        obf = {**self.var_map, **self.func_map, **self.class_map}
        if node.attr in obf:
            node.attr = obf[node.attr]

        return node

    def visit_Call(self, node):
        """ Obfuscate function calls using func_map """
        if isinstance(node.func, ast.Name) and node.func.id in self.func_map:
            node.func.id = self.func_map[node.func.id]
        elif isinstance(node.func, ast.Attribute) and node.func.attr in self.func_map:
            node.func.attr = self.func_map[node.func.attr]

        node.args = [self.visit(arg) for arg in node.args]
        return self.generic_visit(node)

def create_loader(messenger_dir: str):
    """
    Reads aes.py, generator.py and message.py from messenger_dir,
    encodes each via (char+offset)%128, and returns a loader
    snippet that rebuilds them in memory so your normal
    `import messenger.xxx` in client.py just works.
    """
    module_files = ["aes.py", "generator.py", "message.py"]
    loader = ["# --- messenger in-memory loader ---",
              "import sys, types\n",
              "pkg = types.ModuleType('messenger')",
              "sys.modules['messenger'] = pkg\n"]

    for fname in module_files:
        name = fname[:-3]
        src = open(os.path.join(messenger_dir, fname), 'r', encoding='utf-8').read()
        chars, offsets = [], []
        for c in src:
            off = random.randint(1, 50)
            chars.append((ord(c) + off) % 128)
            offsets.append(off)

        # embed the two int‐lists and decode logic
        loader += [
            f"_chars_{name} = {chars}",
            f"_offs_{name} = {offsets}",
            # rebuild source
            f"src_{name} = ''.join(chr((x-y)%128) for x,y in zip(_chars_{name}, _offs_{name}))",
            # exec into module
            f"mod_{name} = types.ModuleType('messenger.{name}')",
            f"exec(src_{name}, mod_{name}.__dict__)",
            f"setattr(pkg, '{name}', mod_{name})",
            f"sys.modules['messenger.{name}'] = mod_{name}\n"
        ]

    loader.append("del sys, types, pkg")
    return "\n".join(loader)

async def build():
    with open(f'{SCRIPT_DIR}/client.py', 'r') as f:
        client = create_loader('messenger') + '\n' + f.read()
    pyfuscator = Pyfuscator()
    pyfuscator.obfuscate_python_file(client, 'messenger-client.py')

if __name__ == "__main__":
    asyncio.run(build())
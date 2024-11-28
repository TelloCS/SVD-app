import ast
from pprint import pp
import pandas as pd

class TableOfFunctions(ast.NodeVisitor):
    def __init__(self):
        self.func_list = []

    def visit(self, node):
        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Call):
                if (isinstance(node.value.func, ast.Name) and not node.value.func.id in self.func_list):
                    self.func_list.append(node.value.func.id)
        if isinstance(node, ast.Call):
            if (isinstance(node.func, ast.Attribute) and not node.func.attr in self.func_list):
                self.func_list.append(node.func.attr)
        self.generic_visit(node)

    def get_func_list(self):
        return self.func_list

class SourceToSink(ast.NodeVisitor):
    def __init__(self, source, sink, code):
        self.source = source
        self.sink = sink
        self.code = code
        self.data = []
    
    def visit_Assign(self, node):
        # possible source
        if (isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == self.source
            ):
            self.data.append({
                            'nodeType': type(node).__name__,
                            'tracked': ast.unparse(node),
                            'line': node.lineno
                            })
            self.generic_visit(node)

        # sink
        if (isinstance(node.targets[0], ast.Name) and node.targets[0].id == self.sink):
            self.data.append({
                            'nodeType': type(node).__name__,
                            'tracked': ast.unparse(node),
                            'line': node.lineno
                            })

    def visit_Call(self, node):
        # possible source
        if isinstance(node.func, ast.Name) and node.func.id == self.source:
            self.data.append({
                        'nodeType': type(node).__name__,
                        'tracked': ast.unparse(node),
                        'line': node.lineno
                        })
            
            self.generic_visit(node)
            
        if isinstance(node.func, ast.Attribute) and node.func.attr == self.source:
            self.data.append({
                        'nodeType': type(node).__name__,
                        'tracked': ast.unparse(node),
                        'line': node.lineno
                        })
            
            unpack_attr = UnpackFuntionCall(self.source)
            unpack_attr.visit(self.code)
            info = unpack_attr.get_data()
            for i in info:
                self.data.append(i)
            
            self.generic_visit(node)

        # sink
        if isinstance(node.func, ast.Attribute) and node.func.attr == self.sink:
            self.data.append({
                        'nodeType': type(node).__name__,
                        'tracked': ast.unparse(node),
                        'line': node.lineno
                        })

            unpack_attr = UnpackFuntionCall(self.sink)
            unpack_attr.visit(self.code)
            info = unpack_attr.get_data()
            for i in info:
                self.data.append(i)

        self.generic_visit(node)
        
    def get_data(self):
        return self.data

class SQLInjectionDetection(ast.NodeVisitor):
    def __init__(self):
        self.injection_patterns = []
        self.data = []
        self.variables = {}

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute) and node.func.attr in ['execute']:
            print(node.args[0])
            if isinstance(node.args[0], ast.Call) and node.args[0].func.attr == 'format':
                print("OK")
                query = node.args[0].func.value
                print(query)
            # if isinstance(node.args[0], ast.Name):
            #     print(ast.unparse(node.args[0]))
        self.generic_visit(node)

    def visit_Assign(self, node):
        if isinstance(node.targets[0], ast.Name):
            if isinstance(node.value, (ast.Call, ast.BinOp, ast.Mod)):
                self.variables[node.targets[0].id] = ast.unparse(node.value)
        self.generic_visit(node)

        # if isinstance(node.value, (ast.BinOp, ast.JoinedStr)):
        #     self.injection_patterns.append(f"Possible SQL injection pattern")
        #     self.data.append({
        #                     'nodeType': type(node).__name__,
        #                     'tracked': ast.unparse(node),
        #                     'line': node.lineno
        #                     })
        self.generic_visit(node)

    def get_patterns(self):
        return '\n'.join(self.injection_patterns)
    
    def get_data(self):
        return self.data
    
    def get_variables(self):
        return self.variables


class UnpackFuntionCall(ast.NodeVisitor):
    def __init__(self, func_name):
        self.func_name = func_name
        self.data = []

    def visit_FunctionDef(self, node):
        if node.name == self.func_name:
            self.data.append({
                        'nodeType': type(node).__name__,
                        'tracked': f'{node.name}({ast.unparse(node.args)})',
                        'line': node.lineno
                        })
            
            for item in node.body:
                if isinstance(item, ast.Assign):
                    self.data.append({
                            'nodeType': type(item).__name__,
                            'tracked': ast.unparse(item),
                            'line': item.lineno
                            })

    def get_data(self) -> list:
        return self.data

#reduce redundancy
def parse_file(code):
    with open(code) as f:
        code = f.read()

    tree = ast.parse(code)
    analyzer = TableOfFunctions()
    analyzer.visit(tree)
    return analyzer.get_func_list()

def flow_of_data(code, source, sink):
    with open(code) as f:
        code = f.read()

    tree = ast.parse(code)
    analyzer = SourceToSink(source, sink, tree)
    analyzer.visit(tree)
    return analyzer.get_data()

def possible_sql_injection(code):
    with open(code) as f:
        code = f.read()

    tree = ast.parse(code)
    analyzer = SQLInjectionDetection()
    analyzer.visit(tree)
    return analyzer.get_variables()

def get_vulnerable_data(code):
    with open(code) as f:
        code = f.read()

    tree = ast.parse(code)
    analyzer = SQLInjectionDetection()
    analyzer.visit(tree)
    return analyzer.get_data()


if __name__ == "__main__":
    table = parse_file('program2.py')
    print(table)

    # flow = flow_of_data('program1.py')
    # print(flow)

    vuln = possible_sql_injection('program2.py')
    print(vuln)
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
    def __init__(self, source, sink):
        self.source = source
        self.sink = sink
        self.data = []
        self.stop_traversal = False
    
    def visit_Assign(self, node):
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

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == self.sink:
                self.data.append({
                            'nodeType': type(node).__name__,
                            'tracked': ast.unparse(node),
                            'line': node.lineno
                            })
                self.stop_traversal = True
                return
        self.generic_visit(node)
        
    def get_data(self):
        return self.data

class SQLInjectionDetection(ast.NodeVisitor):
    def __init__(self):
        self.injection_patterns = []
        self.data = []

    # def visit_Call(self, node):
    #     if isinstance(node.func, ast.Attribute) and node.func.attr == 'execute':
    #         if isinstance(node.args[0], ast.Name):
    #             print(ast.unparse(node.args[0]))
    #     self.generic_visit(node)

    def visit_Assign(self, node):
        if isinstance(node.value, (ast.BinOp, ast.JoinedStr)):
            self.injection_patterns.append(f"Possible SQL injection pattern")
            self.data.append({
                            'nodeType': type(node).__name__,
                            'tracked': ast.unparse(node),
                            'line': node.lineno
                            })
        self.generic_visit(node)

    # if isinstance(node.value, ast.BinOp):
        #     if isinstance(node.value.left, ast.Constant) and isinstance(node.value.right, ast.Name):
        #         self.injection_patterns.append(f"Possible SQL injection pattern")
        #     elif isinstance(node.value.right, ast.Constant) and isinstance(node.value.left, ast.Name):
        #         self.injection_patterns.append(f"Possible SQL injection pattern")

    def get_patterns(self):
        return '\n'.join(self.injection_patterns)
    
    def get_data(self):
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
    analyzer = SourceToSink(source, sink)
    analyzer.visit(tree)
    return analyzer.get_data()

def possible_sql_injection(code):
    with open(code) as f:
        code = f.read()

    tree = ast.parse(code)
    analyzer = SQLInjectionDetection()
    analyzer.visit(tree)
    return analyzer.get_patterns()

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

    flow = get_vulnerable_data('program2.py')
    # print(flow)
    print(flow)

    for data in flow:
        print(data)
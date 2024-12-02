import re
import ast
import pandas as pd

class TableOfFunctions(ast.NodeVisitor):
    def __init__(self):
        self.func_list = []

    def visit(self, node):
        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Call):
                if (isinstance(node.value.func, ast.Name) and not node.value.func.id in self.func_list):
                    self.func_list.append({
                                            'FunctionName': node.value.func.id,
                                            'lineno': node.lineno
                                            })
        if isinstance(node, ast.Call):
            if (isinstance(node.func, ast.Attribute) and not node.func.attr in self.func_list):
                self.func_list.append({
                                        'FunctionName': node.func.attr,
                                        'lineno': node.lineno
                                        })
        self.generic_visit(node)

    def get_func_list(self):
        return self.func_list

class SourceToSink(ast.NodeVisitor):
    def __init__(self, source, sink, code):
        self.source = source
        self.sink = sink
        self.code = code
        self.data = []
    
    def visit_FunctionDef(self, node):
        for child in node.body:
            if isinstance(child, ast.Assign) and not isinstance(child.value, (ast.Name, ast.Subscript, ast.Constant)):
                if isinstance(child.value, ast.Call) and isinstance(child.value.func, ast.Name) and child.value.func.id == self.source:
                    return self.explore(node.body)
                elif isinstance(child.value.func, ast.Attribute) and child.value.func.attr == self.source:
                    return self.explore(node.body)

            if isinstance(child, ast.Expr) and isinstance(child.value, ast.Call):
                if isinstance(child.value.func, ast.Name) and child.value.func.id == self.source:
                    return self.explore(node.body)
                elif isinstance(child.value.func, ast.Attribute) and child.value.func.attr == self.source:
                    return self.explore(node.body)
            
        self.generic_visit(node)

    def explore(self, curr_func):
        valid = False
        for child in curr_func:
            if isinstance(child, ast.Assign) and not isinstance(child.value, (ast.Name, ast.Subscript, ast.Constant)):
                if isinstance(child.value, ast.Call) and isinstance(child.value.func, ast.Name) and child.value.func.id == self.source:
                    valid = True
                elif isinstance(child.value.func, ast.Attribute) and child.value.func.attr == self.source:
                    valid = True
            if isinstance(child, ast.Expr) and isinstance(child.value, ast.Call):
                if isinstance(child.value.func, ast.Name) and child.value.func.id == self.source:
                    valid = True
                elif isinstance(child.value.func, ast.Attribute) and child.value.func.attr == self.source:
                    valid = True
            if valid == True:
                if isinstance(child, ast.Assign) and not isinstance(child.value, ast.Name):
                    self.insert_data(type(child).__name__, ast.unparse(child), child.lineno)
                elif isinstance(child, ast.Return):
                    self.insert_data(type(child).__name__, ast.unparse(child), child.lineno)
                elif isinstance(child, ast.Expr):
                    self.insert_data(type(child.value).__name__, ast.unparse(child), child.lineno)
                    if isinstance(child.value, ast.Call) and isinstance(child.value.func, ast.Attribute) and child.value.func.attr == self.sink:
                        return

    def insert_data(self, nodeType, tracked, line):
        self.data.append({
                        'nodeType': nodeType,
                        'tracked': tracked,
                        'line': line
                        })
        
    def get_data(self):
        return self.data

class SQLInjectionDetection(ast.NodeVisitor):
    def __init__(self):
        self.variables = {}
        self.data = []
        self.detected = []

    def visit_Assign(self, node):
        if not isinstance(node.targets[0], ast.Name):
            return self.generic_visit(node)
        
        if isinstance(node.value, (ast.Call, ast.BinOp, ast.Mod, ast.JoinedStr)):
            self.variables[node.targets[0].id] = node.value
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'execute':
            if isinstance(node.args[0], ast.Call) and node.args[0].func.attr == 'format':
                self.detected.append(f'SQL injection pattern')
                self.insert_data(type(node).__name__, ast.unparse(node), node.lineno)
            elif isinstance(node.args[0], ast.BinOp) and isinstance(node.args[0].op, ast.Mod):
                self.detected.append(f'SQL injection pattern')
                self.insert_data(type(node).__name__, ast.unparse(node), node.lineno)
            elif isinstance(node.args[0], ast.JoinedStr):
                self.detected.append(f'SQL injection pattern')
                self.insert_data(type(node).__name__, ast.unparse(node), node.lineno)
            elif isinstance(node.args[0], ast.Name) and node.args[0].id in self.variables:
                self.sql_vuln_patterns(self.variables[node.args[0].id])

    def sql_vuln_patterns(self, node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
                self.detected.append(f'SQL injection pattern')
                self.insert_data('Assign', ast.unparse(node), node.lineno)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            self.detected.append(f'SQL injection pattern')
            self.insert_data('Assign', ast.unparse(node), node.lineno)
        elif isinstance(node, ast.JoinedStr):
            self.detected.append(f'SQL injection pattern')
            self.insert_data('Assign', ast.unparse(node), node.lineno)
        self.generic_visit(node)

    def insert_data(self, nodeType, tracked, line):
        self.data.append({
                        'nodeType': nodeType,
                        'tracked': tracked,
                        'line': line
                        })
    
    def get_message(self):
        return self.detected

    def get_data(self):
        return self.data

class UnpackFuntionCall(ast.NodeVisitor):
    def __init__(self, func_name):
        self.func_name = func_name
        self.data = []

    def visit_FunctionDef(self, node):
        if node.name == self.func_name:
            self.insert_data(type(node).__name__, f'{node.name}({ast.unparse(node.args)})', node.lineno)
            
            for item in node.body:
                if isinstance(item, ast.Assign):
                    self.insert_data(type(item).__name__, ast.unparse(item), item.lineno)
                    
                if isinstance(item, ast.Return):
                    self.insert_data(type(item).__name__, ast.unparse(item), item.lineno)
                    
    def insert_data(self, nodeType, tracked, line):
        self.data.append({
                        'nodeType': nodeType,
                        'tracked': tracked,
                        'line': line
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

def flow_of_data(code, source='cursor', sink='fetchall'):
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
    return analyzer.get_message()

def get_vulnerable_data(code):
    with open(code) as f:
        code = f.read()

    tree = ast.parse(code)
    analyzer = SQLInjectionDetection()
    analyzer.visit(tree)
    return analyzer.get_data()

if __name__ == "__main__":
    parse = parse_file('fixed.py')
    print(parse)

    flow = flow_of_data('fixed.py')
    print(flow)

    # vuln = possible_sql_injection('program2.py')
    # print(vuln)

    # data = get_vulnerable_data('program2.py')
    # print(data)
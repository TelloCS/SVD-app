import ast
from pprint import pp
import pandas as pd

# from graphviz import Digraph

class Visitor(ast.NodeVisitor):
    def __init__(self):
        # self.tainted_vars = set()
        # self.dot = Digraph()
        self.data = []

    def visit_Assign(self, node):
        # targets -> [Attr, Name], value -> Name, Call, Sub
        # print(node.__dict__)
        # print((ast.unparse(node.targets), ast.unparse(node.value)))
        # print(ast.unparse(node))
        if (isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == 'input'
            ):
            self.generic_visit(node)

    def visit_Call(self, node):
        # func -> name, attr; args -> [const, name, call]
        # print(node.__dict__)
        # print((ast.unparse(node.func), ast.unparse(node.args)))
        # print(ast.unparse(node))
        self.data.append({'nodeType': type(node).__name__,
                          'tracked': ast.unparse(node),
                          'line': node.lineno})
        self.generic_visit(node)

    def get_data(self):
        return self.data
    
    # def visualize(self):
    #     self.dot.render('output/graph', format='png', cleanup=True)

def parse_file(code):
    with open(code) as f:
        code = f.read()

    tree = ast.parse(code)
    analyzer = Visitor()
    analyzer.visit(tree)
    return analyzer.get_data()

# code = parse_file('program1.py')
# print(code)

# for i in code:
#     print(i)



# if __name__ == "__main__":

    # analyzer.visualize()

    # print("\nProgram run:\n")
    # exec(compile(code, "<ast>", mode="exec"))
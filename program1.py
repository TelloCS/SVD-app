class TextHandler:
    def __init__(self, content=""):
        self.content = content

    def update_content(self, new_content):
        self.content = new_content

    def add_suffix(self, suffix):
        self.content += suffix

    def invert_content(self):
        self.content = self.content[::-1]

    def make_uppercase(self):
        self.content = self.content.upper()

    def get_content(self):
        return self.content

def main():
    user_text = input("Input a text: ")

    handler1 = TextHandler()
    handler2 = TextHandler()

    handler1.update_content(user_text)
    handler1.invert_content()

    handler2.update_content(handler1.get_content())
    handler2.make_uppercase()

    print(handler2.get_content())

main()
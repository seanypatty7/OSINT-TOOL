from tkinter import *
from PIL import Image, ImageTk
import main  # Import the main file

class OSINTToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("OSINT Aggregator")
        self.root.geometry("800x1000")  # Adjust the size of the GUI window

        # Frame
        self.frame = LabelFrame(root, padx=25, pady=25)
        self.frame.pack(padx=100, pady=100)

        # Drop-down boxes
        self.clicked = StringVar()
        self.clicked.set("Please select an item")
        self.drop = OptionMenu(self.frame, self.clicked, "Please select an item", "IP Address", "URL", "Hash Value")
        self.drop.pack()

        # Input 
        self.entry = Entry(self.frame, width=30, borderwidth=5, fg='green')
        self.entry.pack()

        # Button
        self.myButton = Button(self.frame, text="Search", command=self.handle_input)
        self.myButton.pack()

        # Text widget to display the report
        self.report_text = Text(self.frame, width=80, height=15, wrap=WORD)
        self.report_text.pack()

        # Label to display the screenshot
        self.screenshot_label = Label(self.root)
        self.screenshot_label.pack()

    def handle_input(self):
        user_input = self.entry.get()
        selection = self.clicked.get()
        # Call the function from the main file and get the report
        # For IP and hash methods, the screenshot path will be None
        report, screenshot_path = main.process_input(selection, user_input)

        # Display the report in the Text widget
        self.report_text.delete(1.0, END)
        self.report_text.insert(END, report)

        # Update the Label widget based on whether a screenshot is available
        if screenshot_path:
            img = Image.open(screenshot_path)
            img = img.resize((600, 400), Image.Resampling.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            self.screenshot_label.configure(image=photo)
            self.screenshot_label.image = photo
        else:
            # For IP and hash methods, or if there's an error with the screenshot
            self.screenshot_label.configure(image='', text='No screenshot available')

        # Reset the input field and drop-down menu after processing
        self.entry.delete(0, END)
        self.clicked.set("Please select an item")

if __name__ == "__main__":
    root = Tk()
    app = OSINTToolGUI(root)
    root.mainloop()

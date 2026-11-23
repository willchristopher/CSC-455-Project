import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Button, Style

from detector import analyze_url, load_model


class PhishingChecker:
    def __init__(self):
        self.setup_gui()

    def setup_gui(self):
        # Set up the window and let the URL box and results expand with it.
        self.root = tk.Tk()
        self.root.tk_setPalette(background="white", foreground="black")
        style = Style(self.root)
        style.theme_use("clam")
        style.configure("TButton", background="white", foreground="black")
        self.root.title("Phishing Website Detection")
        self.root.minsize(640, 355)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(4, weight=1)

        title = tk.Label(self.root, text="Phishing URL Checker", font=("TkDefaultFont", 19, "bold"))
        title.grid(row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(16, 4))

        caption = tk.Label(self.root, text="Paste a full HTTP or HTTPS link. The checker reads it as text.")
        caption.grid(row=1, column=0, columnspan=2, sticky="w", padx=16)

        self.url_entry = tk.Entry(self.root, width=55)
        self.url_entry.grid(row=2, column=0, sticky="ew", padx=(16, 8), pady=12)
        self.url_entry.bind("<Return>", self.check_url)
        self.url_entry.focus_set()

        check_button = Button(self.root, text="Check URL", command=self.check_url)
        check_button.grid(row=2, column=1, padx=(0, 16), pady=12)

        self.status = tk.Label(self.root, text="Result", font=("TkDefaultFont", 13, "bold"))
        self.status.grid(row=3, column=0, columnspan=2, sticky="w", padx=16)

        self.results = ScrolledText(self.root, height=8, width=64, wrap="word", state="disabled")
        self.results.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=16, pady=(4, 8))

        note = tk.Label(self.root, text="For unexpected links, verify the sender and destination separately.")
        note.grid(row=5, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 12))

    def check_url(self, event=None):
        # The button and Enter key use the same detector.
        try:
            result = analyze_url(self.url_entry.get())
        except FileNotFoundError:
            self.show_result("Model file missing", "Restore data/model.json or run train.py.")
            return
        except ValueError as error:
            self.show_result("Check your input", str(error))
            return

        status = "Flagged as possible phishing" if result.flagged else "Below phishing threshold"
        details = [
            f"Hostname: {result.hostname}",
            f"Destination site: {result.site}",
            f"Model score: {result.score:.3f} (flag threshold: {load_model().threshold:.3f})",
            "",
            "The model scores patterns in the address, such as its hostname, path, and query.",
        ]
        self.show_result(status, "\n".join(details))

    def show_result(self, status, details):
        # Replace the old result and make the output read-only again.
        self.status.config(text=status)
        self.results.config(state="normal")
        self.results.delete("1.0", tk.END)
        self.results.insert(tk.END, details)
        self.results.config(state="disabled")


if __name__ == "__main__":
    app = PhishingChecker()
    app.root.mainloop()

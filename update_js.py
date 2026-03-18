import re

def process_js():
    with open('static/js/app.js', 'r') as f:
        js = f.read()

    # Replacements based on our new Tailwind utility classes
    js = js.replace("classList.add('show')", "classList.add('flex-modal')")
    js = js.replace("classList.remove('show')", "classList.remove('flex-modal')")

    js = js.replace("errorEl.classList.add('flex-modal')", "errorEl.classList.add('error-message-show')")
    js = js.replace("errorEl.classList.remove('flex-modal')", "errorEl.classList.remove('error-message-show')")

    # Selection and drag-over
    js = js.replace("classList.add('selected')", "classList.add('selected-row')")
    js = js.replace("classList.remove('selected')", "classList.remove('selected-row')")
    js = js.replace("classList.add('drag-over')", "classList.add('drag-over-area')")
    js = js.replace("classList.remove('drag-over')", "classList.remove('drag-over-area')")

    with open('static/js/app.js', 'w') as f:
        f.write(js)

if __name__ == "__main__":
    process_js()

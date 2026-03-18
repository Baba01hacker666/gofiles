import re

def main():
    with open('static/js/app.js', 'r') as f:
        js = f.read()

    # The issue is that the element has both hidden-modal (display: none !important) and style.display = 'flex'
    # inline style cannot override !important. We should change the JS to use classList for mainApp and loginScreen as well.

    js = js.replace("document.getElementById('loginScreen').style.display = 'none';", "document.getElementById('loginScreen').classList.add('hidden-modal');")
    js = js.replace("document.getElementById('loginScreen').style.display = 'flex';", "document.getElementById('loginScreen').classList.remove('hidden-modal');")

    js = js.replace("document.getElementById('mainApp').style.display = 'flex';", "document.getElementById('mainApp').classList.remove('hidden-modal'); document.getElementById('mainApp').classList.add('flex-modal');")
    js = js.replace("document.getElementById('mainApp').style.display = 'none';", "document.getElementById('mainApp').classList.remove('flex-modal'); document.getElementById('mainApp').classList.add('hidden-modal');")

    with open('static/js/app.js', 'w') as f:
        f.write(js)

if __name__ == "__main__":
    main()

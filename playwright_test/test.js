const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();

  // Navigate to login
  await page.goto('http://localhost:8080');
  await page.waitForTimeout(2000); // give it a moment to render
  await page.screenshot({ path: 'login_screen.png' });
  console.log('Login screen captured.');

  // Attempt login
  await page.fill('#username', 'admin');
  await page.fill('#password', 'admin');
  await page.click('button[type="submit"]');

  await page.waitForTimeout(2000); // give it a moment to load main app
  await page.screenshot({ path: 'main_app.png' });
  console.log('Main app captured.');

  await browser.close();
})();

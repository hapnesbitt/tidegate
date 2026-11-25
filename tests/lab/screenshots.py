"""README screenshots of the lab console (lab data only, never real mail). Runs in Microsoft's Playwright image:

  docker run --rm --network tidegate-lab_tidegate -e LAB_ADMIN_PASSWORD -v "$PWD/tests/lab:/s:ro" \\
      -v "$PWD/docs/screenshots:/out" mcr.microsoft.com/playwright/python:v1.64.1-noble python /s/screenshots.py
"""
import os

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE", "http://172.31.241.30:8080")

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1280, "height": 820})
    page.goto(BASE + "/admin/login")
    page.fill("input[name=username]", "admin")
    page.fill("input[name=password]", os.environ["LAB_ADMIN_PASSWORD"])
    page.click("button.primary")
    page.wait_for_url("**/admin")
    page.screenshot(path="/out/overview.png")
    page.goto(BASE + "/admin/messages?days=1")
    page.screenshot(path="/out/messages.png")
    page.goto(BASE + "/admin/quarantine?category=impostor")
    page.click("table.log tbody tr td:nth-child(5) a")
    page.wait_for_load_state()
    page.screenshot(path="/out/item.png", full_page=True)
    browser.close()
print("screenshots written")

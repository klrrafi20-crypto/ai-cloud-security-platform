"""
Launches the Streamlit dashboard as a native-looking desktop window,
instead of opening in a browser tab.
"""

import subprocess
import time
import webview

# Start the Streamlit server in the background (headless, no browser auto-open)
streamlit_process = subprocess.Popen(
    ["python", "-m", "streamlit", "run", "dashboard.py",
     "--server.headless", "true"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)

# Give the server a couple seconds to start up before we try to open it
time.sleep(3)

# Open a plain app-style window pointing at the local dashboard
webview.create_window("AI Powered Cloud Security Platform", "http://localhost:8501", width=1300, height=850)
webview.start()

# When the window is closed, shut down the Streamlit server too
streamlit_process.terminate()
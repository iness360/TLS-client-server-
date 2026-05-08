Step 1 — Open Docker Desktop
Step 2 — Open PowerShell
Step 3 — Go to Your Project Folder :type : 
 cd $HOME\pq-tls-demo
( change the directory to where you downloaded the folders it doesn't need to be HOME ) 
Step 4 — Start the Servers
type : powershelldocker compose up -d
Wait until you see:
✔ Container pq-server-classical  Started
✔ Container pq-server-pq         Started
✔ Container pq-server-hybrid     Started
Step 5 — Verify They Are Running
type: powershelldocker ps
You should see 3 containers with status Up.
Step 6 — Open the Dashboard
type: powershellstart dashboard\index.html
Your browser opens the dashboard automatically.
step 7 - 
type: powershell -ExecutionPolicy Bypass -File benchmark.ps1
wait for the ports to run 
after servers done running 
then go back to the dashboard and click the green botton 
these are the results visualized 
 step 8-Run the Analysis Script
type: powershellpython results\analyze_tls.py

What You Should See
============================================================
  PQ-TLS Analysis Script
============================================================

Loading latency_raw.csv ...
  Rows loaded: 40
  Modes found: ['classical', 'pq']
  classical  : mean=191.57 ms  median=...
  pq         : mean=213.35 ms  median=...

Generating graphs...
    ✓  01_latency_boxplot.png
    ✓  02_latency_barplot.png
    ✓  03_latency_per_run.png
    ...

All done! Open the results/ folder to see your graphs.

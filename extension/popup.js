document.addEventListener('DOMContentLoaded', function() {
    const analyzeButton = document.getElementById('analyze-page');
    const reportButton = document.getElementById('report-phishing');
    const settingsLink = document.getElementById('settings-link');
    const statusContainer = document.getElementById('status-container');
    const resultsContainer = document.getElementById('results-container');
    const urlScore = document.getElementById('url-score');
    const contentScore = document.getElementById('content-score');
    
    // Function to update status indicator
    function updateStatus(status, score = null) {
        statusContainer.className = 'status-indicator';
        
        if (score > 0.8) {
            statusContainer.classList.add('status-danger');
            statusContainer.textContent = 'High Risk!';
        } else if (score > 0.6) {
            statusContainer.classList.add('status-warning');
            statusContainer.textContent = 'Suspicious';
        } else if (score !== null) {
            statusContainer.classList.add('status-safe');
            statusContainer.textContent = 'Safe';
        } else {
            statusContainer.textContent = status;
        }
    }
    
    // Function to analyze current page
    async function analyzePage() {
        updateStatus('Analyzing...');
        
        // Send message to content script
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            chrome.tabs.sendMessage(tabs[0].id, {action: 'analyzeNow'}, function(response) {
                if (chrome.runtime.lastError) {
                    updateStatus('Error: Could not analyze page');
                    return;
                }
                
                if (response && response.urlScore !== undefined) {
                    resultsContainer.style.display = 'block';
                    updateStatus('Analysis Complete', response.urlScore);
                    
                    urlScore.textContent = `URL Risk Score: ${(response.urlScore * 100).toFixed(1)}%`;
                    if (response.contentScore !== undefined) {
                        contentScore.textContent = `Content Risk Score: ${(response.contentScore * 100).toFixed(1)}%`;
                    }
                }
            });
        });
    }
    
    // Function to report current page as phishing
    async function reportPhishing() {
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            const url = tabs[0].url;
            
            fetch('http://localhost:5000/api/report_feedback', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    url: url,
                    is_phishing: true,
                    content_type: 'url'
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    updateStatus('Reported successfully');
                    setTimeout(() => {
                        window.close();
                    }, 1500);
                } else {
                    updateStatus('Error reporting');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                updateStatus('Error reporting');
            });
        });
    }
    
    // Add event listeners
    analyzeButton.addEventListener('click', analyzePage);
    reportButton.addEventListener('click', reportPhishing);
    settingsLink.addEventListener('click', function(e) {
        e.preventDefault();
        chrome.runtime.openOptionsPage();
    });
    
    // Analyze page when popup opens
    analyzePage();
}); 
// API endpoint
const API_URL = 'http://localhost:5000/api';

// Function to analyze URL
async function analyzeURL(url) {
    try {
        const response = await fetch(`${API_URL}/analyze_url`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url })
        });
        
        return await response.json();
    } catch (error) {
        console.error('Error analyzing URL:', error);
        return null;
    }
}

// Function to analyze email content
async function analyzeEmailContent(content) {
    try {
        const response = await fetch(`${API_URL}/analyze_email`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email_content: content })
        });
        
        return await response.json();
    } catch (error) {
        console.error('Error analyzing email content:', error);
        return null;
    }
}

// Function to report feedback
async function reportFeedback(data) {
    try {
        const response = await fetch(`${API_URL}/report_feedback`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
        
        return await response.json();
    } catch (error) {
        console.error('Error reporting feedback:', error);
        return null;
    }
}

// Function to create warning banner
function createWarningBanner(message, riskScore) {
    const banner = document.createElement('div');
    banner.className = 'phishing-warning-banner';
    
    const color = riskScore > 0.8 ? '#ff4444' : 
                 riskScore > 0.6 ? '#ffaa33' : '#ffdd33';
    
    banner.style.backgroundColor = color;
    
    banner.innerHTML = `
        <div class="warning-content">
            <strong>⚠️ Phishing Warning</strong>
            <p>${message}</p>
            <p>Risk Score: ${(riskScore * 100).toFixed(1)}%</p>
            <div class="warning-actions">
                <button class="report-false-positive">Report False Positive</button>
                <button class="proceed-anyway">Proceed Anyway</button>
            </div>
        </div>
    `;
    
    document.body.insertBefore(banner, document.body.firstChild);
    
    // Add event listeners
    banner.querySelector('.report-false-positive').addEventListener('click', () => {
        reportFeedback({
            url: window.location.href,
            is_phishing: false,
            content_type: 'url'
        });
        banner.remove();
    });
    
    banner.querySelector('.proceed-anyway').addEventListener('click', () => {
        banner.remove();
    });
}

// Main function to analyze current page
async function analyzePage() {
    // Analyze URL
    const urlResult = await analyzeURL(window.location.href);
    
    if (urlResult && urlResult.is_phishing) {
        createWarningBanner(
            'This website has been identified as a potential phishing threat.',
            urlResult.risk_score
        );
    }
    
    // Check if page is an email (e.g., Gmail, Outlook)
    const emailContent = document.querySelector('.email-content');
    if (emailContent) {
        const emailResult = await analyzeEmailContent(emailContent.innerText);
        
        if (emailResult && emailResult.is_phishing) {
            createWarningBanner(
                'This email has been identified as a potential phishing threat.',
                emailResult.risk_score
            );
        }
    }
}

// Run analysis when page loads
window.addEventListener('load', analyzePage);

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'analyzeNow') {
        analyzePage();
    }
}); 
import os
import unicodedata

def clean_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            text = f.read()
            
        original_text = text
        
        # We want to remove characters that are emojis, 
        # except the police car light \U0001f6a8 (🚨)
        
        cleaned = []
        for c in text:
            if c == '\U0001f6a8': # 🚨
                cleaned.append(c)
                continue
                
            cat = unicodedata.category(c)
            # Remove symbols and other emoji-like chars
            # 'So' is Symbol, Other (contains most emojis)
            # 'Sk' is Symbol, Modifier
            if cat in ('So', 'Sk') and ord(c) > 127:
                # Also check if it's a known non-emoji symbol we want to keep?
                pass # skip
            elif c in ['\u25bc', '\u2500', '\u2b21', '\u2717', '\u2713', '\u26a1', '\ud83d', '\ud83c', '\u2502', '\u2514', '\u251c', '\u2550', '\u2705', '\u274c', '\u26a0', '\ud83d', '\ud83d', '\ud83c', '\ud83c', '\ud83d', '\ud83d']:
                pass # Skip explicit list of some shapes
            else:
                cleaned.append(c)
                
        new_text = "".join(cleaned)
        
        # Additionally, do some targeted string replacements
        new_text = new_text.replace(" Analyzing:", "Analyzing:")
        new_text = new_text.replace(" PhishGuard++ Tier 1", "PhishGuard++ Tier 1")
        new_text = new_text.replace(" Failed", "Failed")
        new_text = new_text.replace(" Reported!", "Reported!")
        new_text = new_text.replace(" Failed — retry", "Failed — retry")
        new_text = new_text.replace(" PhishGuard++ Popup Loaded", "PhishGuard++ Popup Loaded")
        new_text = new_text.replace("️ Suspicious:", "Suspicious:")
        
        if new_text != original_text:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(new_text)
            print(f"Cleaned {filepath}")
            
    except Exception as e:
        print(f"Error processing {filepath}: {e}")

for root, dirs, files in os.walk('.'):
    if 'venv' in root or '.git' in root or '__pycache__' in root:
        continue
    for file in files:
        if file.endswith(('.py', '.js', '.html', '.md')):
            clean_file(os.path.join(root, file))

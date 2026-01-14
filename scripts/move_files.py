import shutil
import os

ROOT = r"D:\Programming\Hackathon\DevConquest 2k26\KazeCoders"

moves = [
    (os.path.join(ROOT, 'FTP- Unknown-56.pcap'), os.path.join(ROOT, 'data', 'pcap', 'FTP- Unknown-56.pcap')),
    (os.path.join(ROOT, 'NotReadme.txt'), os.path.join(ROOT, 'docs', 'NotReadme.txt')),
    (os.path.join(ROOT, 'frontend', 'README.md'), os.path.join(ROOT, 'docs', 'frontend_README.md')),
]

for src, dst in moves:
    try:
        if os.path.exists(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.move(src, dst)
            print(f"Moved: {src} -> {dst}")
        else:
            print(f"Not found (skipping): {src}")
    except Exception as e:
        print(f"Error moving {src} -> {dst}: {e}")

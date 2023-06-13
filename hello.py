import os
import webbrowser

file_path = './web_scan_report.html'

# HTML 파일의 절대 경로를 얻기 위해 현재 작업 디렉터리를 사용합니다
current_dir = os.path.dirname(os.path.abspath(__file__))
absolute_path = os.path.join(current_dir, file_path)

# 웹 브라우저로 HTML 파일 열기
webbrowser.open('file://' + absolute_path)

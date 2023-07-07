import json
import html
import matplotlib.pyplot as plt


def load_json():
    json_file = './test/example/dvwa/Testing_Result.json'

    with open(json_file, 'r') as f:
        data = json.load(f)

    return data


def generate_report(results):
    # JSON 데이터를 테이블 형식의 테스팅 정보로 변환
    testing_info = "<table>"
    testing_info += """
        <tr>
            <th style="width: 200px; max-width: 200px;">Vulnerability</th>
            <th>URL</th>
            <th style="width: 100px; max-width: 120px;">Method</th>
            <th>Payload</th>
        </tr>
    """
    for result in results:
        vulnerability = html.escape(result['Vulnerability'])
        url = f"<a href='{html.escape(result['URL'])}'>{html.escape(result['URL'])}</a>"
        method = html.escape(result['Method']).upper()
        payload = result['Payload']

        # Payload이 딕셔너리인 경우 한 줄에 한 개씩 상자로 표시
        if isinstance(payload, dict):
            payload_items = ""
            for key, value in payload.items():
                key = html.escape(str(key))
                value = html.escape(str(value))
                payload_items += f"<div class='payload-item'><span class='payload-key'>{key}:</span> <span class='payload-value'>{value}</span></div><br>"

            payload = f"<div class='payload-box'>{payload_items}</div>"
        else:
            # Payload이 리스트인 경우 각 항목을 한 줄에 한 개씩 표시
            if isinstance(payload, list):
                payload_items = ""
                for item in payload:
                    item = html.escape(str(item))
                    payload_items += f"<div class='payload-item'>{item}</div><br>"
                payload = payload_items
            else:
                payload = html.escape(str(payload))

        card = f"""
            <tr>
                <td>{vulnerability}</td>
                <td>{url}</td>
                <td>{method}</td>
                <td>{payload}</td>
            </tr>
        """
        testing_info += card

    testing_info += "</table>"

    # 취약점 종류별 개수를 원형 그래프로 표시
    vulnerability_counts = {}
    for result in results:
        vulnerability = html.escape(result['Vulnerability'])
        if vulnerability in vulnerability_counts:
            vulnerability_counts[vulnerability] += 1
        else:
            vulnerability_counts[vulnerability] = 1

    vulnerabilities = list(vulnerability_counts.keys())
    counts = list(vulnerability_counts.values())

    plt.figure(figsize=(6, 6))
    plt.pie(counts, labels=vulnerabilities, autopct='%1.1f%%')
    plt.axis('equal')

    # 취약점 개수별 테이블 생성
    vulnerability_table = "<table>"
    vulnerability_table += """
        <tr>
            <th>Vulnerability</th>
            <th>Count</th>
        </tr>
    """
    for vulnerability, count in vulnerability_counts.items():
        vulnerability_table += f"<tr><td>{vulnerability}</td><td>{count}</td></tr>"

    total_count = sum(vulnerability_counts.values())
    vulnerability_table += f"<tr><td colspan='4' style='text-align: right;'><b>Total:</b> {total_count} </td></tr>"
    vulnerability_table += "</table>"

    # HTML 템플릿 생성
    html_template = """
    <html>
    <head>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;700&display=swap');

            body {{
                font-family: 'Montserrat', sans-serif;
                line-height: 1.5;
                color: #333333;
                background-color: #f9f9f9;
                padding: 30px;
                margin: 0;
            }}

            h1 {{
                font-size: 28px;
                text-align: center;
                margin-bottom: 30px;
            }}

            .chart-container {{
                display: flex;
                justify-content: center;
                margin-bottom: 30px;
            }}

            .chart-container img {{
                max-width: 100%;
                height: auto;
            }}

            .container {{
                margin-bottom: 30px;
            }}

            table {{
                border-collapse: collapse;
                width: 100%;
                margin-bottom: 20px;
                table-layout: auto;
            }}

            th,
            td {{
                padding: 10px 15px;
                border: 1px solid #e0e0e0;
                word-wrap: break-word;
                text-align: center;
            }}

            th {{
                background-color: #f5f5f5;
                font-weight: bold;
            }}

            .payload-box {{
                flex-wrap: wrap;
                margin-top: 10px;
            }}

            .payload-item {{
                margin-bottom: 3px;
                text-align: left;
            }}

            .payload-key {{
                font-weight: bold;
            }}

            .payload-value {{
                margin-left: 3px;
            }}
        </style>
    </head>

    <body>
        <h1>웹 취약점 점검 레포트</h1>

        <div class="chart-container">
            <img src="vulnerability_chart.png" alt="Vulnerability Chart">
        </div>

        <br>
        <br>

        <div class="container">
            <h3>Vulnerability Summary</h2>
            {vulnerability_table}
        </div>

        <br>
        <br>
        
        <div class="container">
            <h3>Testing Information</h2>
            {testing_info}
        </div>
    </body>

    </html>
    """

    # HTML 파일로 저장
    with open('./test/example/dvwa/web_scan_report.html', 'w', encoding='utf-8') as f:
        f.write(html_template.format(vulnerability_table=vulnerability_table, testing_info=testing_info))

    # 그래프 이미지 파일로 저장
    plt.savefig('./test/example/dvwa/vulnerability_chart.png', bbox_inches='tight')

    print("웹 취약점 스캐너 레포트가 생성되었습니다. \n./test/example/dvwa/web_scan_report.html 파일과 ./test/example/dvwa/vulnerability_chart.png 파일을 확인하세요.")


if __name__ == '__main__':
    data = load_json()

    # 레포트 생성
    generate_report(data)

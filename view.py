import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import csv
import os


def robust_parse(filename, expected_cols):
    rows = []
    if not os.path.exists(filename): return pd.DataFrame()
    with open(filename, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        header = lines[0].strip().replace('"', '').split(',')
        for line in lines[1:]:
            line = line.strip().strip('"')
            parts = list(csv.reader([line]))[0]
            if len(parts) > expected_cols:
                rows.append(parts[:3] + [",".join(parts[3:-1])] + [parts[-1]])
            else:
                rows.append(parts)
    return pd.DataFrame(rows, columns=header)

# Carga dos logs
http_logs = robust_parse('http_logs.csv', 5)
db_logs   = pd.read_csv('db_logs.csv')
waf_logs  = pd.read_csv('waf_logs.csv')

for df in [http_logs, db_logs, waf_logs]:
    df['timestamp'] = pd.to_datetime(df['timestamp'])

tentativas = http_logs[http_logs['params'].str.contains('UNION|SELECT|--', na=False, case=False)].set_index('timestamp').resample('1min').size()
sucessos_db = db_logs[(db_logs['source'] == 'unknown-src') & (db_logs['status'] == 'OK')].set_index('timestamp').resample('1min').size()


# Localiza o primeiro minuto com atividade
minuto_inicial = tentativas[tentativas > 0].index.min()
fim_minuto_inicial = minuto_inicial + pd.Timedelta(minutes=1)

# Dentro desse minuto, busca o primeiro alerta real no WAF (precisão por segundo)
alertas_no_inicio = waf_logs[
    (waf_logs['rule'] != 'NORMAL') & 
    (waf_logs['timestamp'] >= minuto_inicial) & 
    (waf_logs['timestamp'] < fim_minuto_inicial)
]
primeiro_incidente = alertas_no_inicio['timestamp'].min() if not alertas_no_inicio.empty else minuto_inicial


# Critério: minuto com maior volume combinado de tentativas HTTP + queries maliciosas no banco
combined       = tentativas.add(sucessos_db, fill_value=0)
pico_incidente = combined.idxmax()

plt.figure(figsize=(16, 8))
ax = plt.gca()

plt.plot(tentativas.index, tentativas.values, label='Tentativas de Ataque (Rede)', color='black', marker='o', linewidth=2)
plt.plot(sucessos_db.index, sucessos_db.values, label='Explorações com Sucesso (Impacto no Banco)', color='green', marker='o', linewidth=2)

# Marcos Verticais com os horários exatos detectados
plt.axvline(primeiro_incidente, color='green', linestyle=':', linewidth=2, 
            label=f'Primeiro Incidente ({primeiro_incidente.strftime("%H:%M:%S")})')

plt.axvline(pico_incidente, color='red', linestyle='--', linewidth=2, 
            label=f'Pico do Incidente ({pico_incidente.strftime("%H:%M:%S")})')

ax.set_xlim([pd.Timestamp('2026-03-15 08:41:00'), sucessos_db.index.max() + pd.Timedelta(minutes=2)])
ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=1))
ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))

plt.title('ATIVIDADE TEMPORAL DO INCIDENTE', fontsize=16, fontweight='bold')
plt.xlabel('Horário')
plt.ylabel('Quantidade de Eventos')
plt.legend(loc='upper left')
plt.grid(True, alpha=0.3)
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('atividade_temporal_final.png')
plt.show()

print(f"Detecção Finalizada:")
print(f"Início exato: {primeiro_incidente}")
print(f"Pico exato: {pico_incidente}")

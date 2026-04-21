# sqli-incident-analyzer

Análise de logs de segurança com detecção automática de incidentes de SQL Injection.

Desenvolvido como solução de análise do incidente ocorrido na VendasOnline em 15/03/2026, o projeto localiza automaticamente a primeira anomalia e o pico do incidente a partir de logs brutos — sem valores hardcoded e sem intervenção manual.



## Como funciona

**1. Carregamento robusto**
Logs HTTP com payloads SQL contêm vírgulas internas (`UNION SELECT email,password`) que quebram parsers CSV convencionais. O parser do projeto detecta esse caso e reconstrói o campo corretamente antes de processar.

**2. Detecção automática dos marcos temporais**

- **Primeira anomalia:** localiza o primeiro minuto com tentativas de ataque nas requisições HTTP e refina até o segundo exato usando o primeiro alerta do WAF dentro desse minuto
- **Pico do incidente:** agrega tentativas HTTP e queries maliciosas bem-sucedidas no banco por janela de 1 minuto e identifica o de maior volume combinado

**3. Visualização**
Gera um gráfico com as duas séries temporais — tentativas de rede e explorações confirmadas no banco — marcando visualmente a primeira anomalia e o pico do incidente.

---

## Estrutura esperada dos logs

O projeto espera cinco arquivos CSV no diretório de execução:

| Arquivo | Conteúdo |
|---|---|
| `http_logs.csv` | Requisições HTTP com método, endpoint, parâmetros e status |
| `db_logs.csv` | Queries executadas no banco com fonte, operação e status |
| `waf_logs.csv` | Eventos do WAF com IP, país, ação e regra disparada |
| `auth_logs.csv` | Eventos de autenticação e acesso entre serviços |
| `app_logs.csv` | Logs da aplicação com nível e mensagem |

---

## Instalação

```bash
git clone https://github.com/huantssousa/sqli-incident-analyzer
cd sqli-incident-analyzer
pip install -r requirements.txt
```

**Dependências:**
```
pandas
matplotlib
```

## Saída

![Gráfico de atividade temporal do incidente](atividade_temporal_final.png)

O gráfico exibe:
- Linha preta — tentativas de ataque detectadas nas requisições HTTP
- Linha verde — explorações bem-sucedidas confirmadas no banco de dados
- Linha verde pontilhada — marco da primeira anomalia
- Linha vermelha tracejada — marco do pico do incidente

---

## Segurança

Arquivos de log e saídas geradas estão listados no `.gitignore` e não devem ser versionados. Logs contêm dados sensíveis — IPs, payloads de ataque e informações de clientes.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


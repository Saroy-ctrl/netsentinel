# dashboard/ — SOC console (M4)

Streamlit app, five pages (docs/03_architecture.md §5). Talks only to the API through `api_client.py`,
typed with `nscore.contracts`. Offline mode reads `nscore/contracts/fixtures/` directly, so you can start
before the API exists.

`streamlit run dashboard/app.py`

### Скрипт для скачивания отчетов по хостам проекта

1. Получить авторизационный токен для доступа к ЛК ScanFactory
2. Экспортировать переменную:   
`export SF_ACCESS_TOKEN='Bearer <token>'`
3. Эскортировать переменную вашего ЛК:   
`export SF_API_URL=https://example.sf-cloud.ru/api/`
4. Запустить документацию по скрипту:   
`python -m get_reports --h`
5. Примеры запуска скрипта:
- Скачать HTML отчеты для указанных активных хостов в проекте project_ID:   
`python -m get_reports --project project_ID --hosts 127.0.0.1 --ext html`

- Скачать pdf отчеты для всех скрытых хостов проекта project_ID:   
`python -m get_reports --project <project_ID> --hosts all --ext pdf --hidden`


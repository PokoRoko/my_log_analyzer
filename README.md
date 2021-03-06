### **Логи:**  
семпл лога: nginx-access-ui.log-20170630.gz  
шаблон названия логов интерфейса соответствует названию сэмпла (ну, только время меняется)  
так вышло, что логи могут быть и plain и gzip  
лог ротируется раз в день  
опять же, так вышло, что логи интерфейса лежат в папке с логами других сервисов  


### **Отчет:**
count - сколько раз встречается URL, абсолютное значение  
count_perc - сколько раз встречается URL, в процентнах относительно общего числа запросов  
time_sum - суммарный $request_time для данного URL'а, абсолютное значение  
time_perc - суммарный $request_time для данного URL'а, в процентах относительно общего $request_time всех запросов  
time_avg - средний $request_time для данного URL'а  
time_max - максимальный $request_time для данного URL'а  
time_med - медиана $request_time для данного URL'а  


## **Задача: реализовать анализатор логов log_analyzer.py .**
### **Основная функциональность:**
1. Скрипт обрабатывает при запуске последний (со самой свежей датой в имени, не по mtime файла!) лог в LOG_DIR , в
результате работы должен получится отчет как в report-2017.06.30.html (для корректной работы нужно будет найти и
принести себе на диск jquery.tablesorter.min.js ). То есть скрипт читает лог, парсит нужные поля, считает необходимую
статистику по url'ам и рендерит шаблон report.html (в шаблоне нужно только подставить $table_json ). Ситуация, что
логов на обработку нет возможна, это не должно являться ошибкой.
2. Если удачно обработал, то работу не переделывает при повторном запуске. Готовые отчеты лежат в REPORT_DIR . В отчет
попадает REPORT_SIZE URL'ов с наибольшим суммарным временем обработки ( time_sum ).
3. Скрипту должно быть возможно указать считать конфиг из другого файла, передав его путь через --config . У пути
конфига должно быть дефолтное значение. Если файл не существует или не парсится, нужно выходить с ошибкой.
4. В переменной config находится конфиг по умолчанию (и его не надо выносить в файл). В конфиге, считанном из файла,
могут быть переопределены перменные дефолтного конфига (некоторые, все или никакие, т.е. файл может быть пустой) и
они имеют более высокий приоритет по сравнению с дефолтным конфигом. Таким образом, результирующий конфиг
получается слиянием конфига из файла и дефолтного, с приоритетом конфига из файла. Ситуацию, когда конфига на
диске не оказалось, нужно исключить.
5. Использовать конфиг как глобальную переменную запрещено, т.е. обращаться в своем функционале к нему так, как будто
он глобальный - нельзя. Нужно передавать как аргумент.
6. Использовать сторонние библиотеки запрещено.
7. скрипт должен писать логи через библиотеку logging в формате '[%(asctime)s] %(levelname).1s %(message)s' c датой в
виде '%Y.%m.%d %H:%M:%S' (logging.basicConfig позволит настроить это в одну строчку). Допускается только
использование уровней info , error и exception . Путь до логфайла указывается в конфиге, если не указан, лог должен
писаться в stdout (параметр filename в logging.basicConfig может принимать значение None как раз для этого).
8. все возможные "неожиданные" ошибки должны попадать в лог вместе с трейсбеком (посмотрите на logging.exception).
Имеются в виду ошибки непредусмотренные логикой работы, приводящие к остановке обработки и выходу: баги, нажатие
ctrl+C, кончилось место на диске и т.п.

9. должно быть предусмотрено оповещение о том, что большую часть анализируемого лога не удалось распарсить
(например, потому что сменился формат логирования). Для этого нужно задаться относительным (в долях/процентах)
порогом ошибок парсинга и при его превышании писать в лог, затем выходить.
Тестирование:
10. на скрипт должны быть написаны тесты с использованием библиотеки unittest (https://pymotw.com/2/unittest/). Имя
скрипта с тестами должно начинаться со слова test . Тестируемые кейсы и структура тестов определяется
самостоятельно (без фанатизма, в принципе достаточно функциональных тестов


### **Запуск проекта**
1) Установка зависимостей не требуется
2) Запуск `python3 my_log_analyzer.py`
3) Указать кастомный конфиг `python3 my_log_analyzer.py --config ./path/config.cfg`

### **Параметры конфиг файла**
`REPORT_SIZE` - Количество url включенный в отчет  
`REPORT_DIR` - Папка куда складываем отчеты  
`LOG_DIR` - Папка где лежат логи NGINX  
`ALLOW_PERC_ERRORS` - Максимально допустимое количество ошибок при чтении лога в процентах  
`LOGGING_FILE` - Имя файла куда будут писаться логи сервиса. При None выводит в stdout 
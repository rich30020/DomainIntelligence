import json
import re

from PySide6.QtCore import Qt, QThread
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QMessageBox,
    QFrame,
    QCheckBox,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QHeaderView,
    QFileDialog,
    QScrollArea,
    QGroupBox,
    QTabWidget,
)

from gui.scan_worker import ScanWorker
from services.risk_scoring_service import RiskScoringService


class MainWindow(QMainWindow):
    def __init__(self, scanner_engine=None, database_service=None):
        super().__init__()

        self.scanner_engine = scanner_engine
        self.database_service = database_service
        self.risk_scoring_service = RiskScoringService()

        self.scan_thread = None
        self.scan_worker = None

        self.image_path = None
        self.comparison_image_path = None
        self.module_status_labels = {}

        self.setWindowTitle("Domain Intelligence")
        self.setMinimumSize(1050, 760)
        self.resize(1280, 900)

        self.create_interface()
        self.load_history()

    def create_interface(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        page = QWidget()
        scroll.setWidget(page)
        self.setCentralWidget(scroll)

        root = QVBoxLayout(page)
        root.setContentsMargins(30, 24, 30, 30)
        root.setSpacing(18)

        # Header
        header_row = QHBoxLayout()
        title_col = QVBoxLayout()

        title = QLabel("DOMAIN INTELLIGENCE")
        title.setObjectName("appTitle")
        subtitle = QLabel("DOMAIN ENUMERATION  •  BRAND PROTECTION  •  THREAT INTELLIGENCE")
        subtitle.setObjectName("appSubtitle")

        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        header_row.addLayout(title_col)
        header_row.addStretch()

        self.header_status = QLabel("PRONTO")
        self.header_status.setObjectName("readyBadge")
        header_row.addWidget(self.header_status, 0, Qt.AlignmentFlag.AlignTop)
        root.addLayout(header_row)

        # Scan card
        scan_card = QFrame()
        scan_card.setObjectName("card")
        scan_layout = QVBoxLayout(scan_card)
        scan_layout.setContentsMargins(22, 20, 22, 22)
        scan_layout.setSpacing(14)

        scan_heading = QLabel("Nuova scansione")
        scan_heading.setObjectName("sectionTitle")
        scan_layout.addWidget(scan_heading)

        domain_label = QLabel("DOMINIO DA ANALIZZARE")
        domain_label.setObjectName("fieldLabel")
        scan_layout.addWidget(domain_label)

        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("es. example.com")
        self.domain_input.setMinimumHeight(46)
        scan_layout.addWidget(self.domain_input)

        modules_heading = QLabel("Moduli di analisi")
        modules_heading.setObjectName("subsectionTitle")
        scan_layout.addWidget(modules_heading)

        modules_grid = QGridLayout()
        modules_grid.setHorizontalSpacing(12)
        modules_grid.setVerticalSpacing(10)

        domain_group = QGroupBox("ANALISI DOMINIO")
        domain_group.setObjectName("moduleGroup")
        domain_grid = QVBoxLayout(domain_group)
        domain_grid.setSpacing(8)

        self.domain_scanner_check = self._create_module_checkbox(
            "Domain Scanner", "RDAP e record DNS", True, "domain_scanner"
        )
        self.subdomain_check = self._create_module_checkbox(
            "Subdomain Finder", "Ricerca passiva di sottodomini", True, "subdomain_finder"
        )
        self.similar_domain_check = self._create_module_checkbox(
            "Similar Domain Finder", "Varianti e domini simili", True, "similar_domain_analyzer"
        )
        self.threat_intel_check = self._create_module_checkbox(
            "Threat Intelligence", "Confronto con IOC locali", True, "threat_intel_analyzer"
        )

        for checkbox in (
            self.domain_scanner_check,
            self.subdomain_check,
            self.similar_domain_check,
            self.threat_intel_check,
        ):
            domain_grid.addWidget(self._module_row(checkbox))

        image_group = QGroupBox("ANALISI IMMAGINI LOCALI")
        image_group.setObjectName("moduleGroup")
        image_grid = QVBoxLayout(image_group)
        image_grid.setSpacing(8)

        self.image_hash_check = self._create_module_checkbox(
            "Image Hash Analyzer", "Calcolo delle impronte percettive", False, "image_hash_analyzer"
        )
        self.image_similarity_check = self._create_module_checkbox(
            "Image Similarity Analyzer", "Confronto tra due immagini", False, "image_similarity_analyzer"
        )
        self.logo_detector_check = self._create_module_checkbox(
            "Logo Detector", "Euristica basata sul nome del file", False, "logo_detector"
        )

        for checkbox in (
            self.image_hash_check,
            self.image_similarity_check,
            self.logo_detector_check,
        ):
            image_grid.addWidget(self._module_row(checkbox))

        modules_grid.addWidget(domain_group, 0, 0)
        modules_grid.addWidget(image_group, 0, 1)
        modules_grid.setColumnStretch(0, 1)
        modules_grid.setColumnStretch(1, 1)
        scan_layout.addLayout(modules_grid)

        # Local image selectors
        files_group = QGroupBox("FILE IMMAGINE")
        files_group.setObjectName("moduleGroup")
        files_layout = QVBoxLayout(files_group)
        files_layout.setSpacing(10)

        first_row = QHBoxLayout()
        self.image_select_button = QPushButton("Scegli prima immagine")
        self.image_select_button.setObjectName("secondaryButton")
        self.image_select_button.clicked.connect(self.select_image)
        self.image_path_label = QLabel("Nessuna prima immagine selezionata")
        self.image_path_label.setObjectName("filePath")
        self.image_path_label.setWordWrap(True)
        first_row.addWidget(self.image_select_button)
        first_row.addWidget(self.image_path_label, 1)
        files_layout.addLayout(first_row)

        second_row = QHBoxLayout()
        self.comparison_image_button = QPushButton("Scegli seconda immagine")
        self.comparison_image_button.setObjectName("secondaryButton")
        self.comparison_image_button.clicked.connect(self.select_comparison_image)
        self.comparison_image_label = QLabel("Nessuna seconda immagine selezionata")
        self.comparison_image_label.setObjectName("filePath")
        self.comparison_image_label.setWordWrap(True)
        second_row.addWidget(self.comparison_image_button)
        second_row.addWidget(self.comparison_image_label, 1)
        files_layout.addLayout(second_row)

        hint = QLabel(
            "Le immagini restano sul computer: vengono lette localmente e non caricate online."
        )
        hint.setObjectName("hint")
        files_layout.addWidget(hint)
        scan_layout.addWidget(files_group)

        self.scan_button = QPushButton("AVVIA ANALISI")
        self.scan_button.setObjectName("primaryButton")
        self.scan_button.setMinimumHeight(48)
        self.scan_button.clicked.connect(self.start_scan)
        scan_layout.addWidget(self.scan_button)

        root.addWidget(scan_card)

        # Activity
        activity_card = QFrame()
        activity_card.setObjectName("card")
        activity_layout = QVBoxLayout(activity_card)
        activity_layout.setContentsMargins(20, 16, 20, 16)
        activity_layout.setSpacing(10)

        activity_title = QLabel("Stato attività")
        activity_title.setObjectName("sectionTitle")
        activity_layout.addWidget(activity_title)

        self.status_label = QLabel("In attesa di una scansione.")
        self.status_label.setObjectName("statusText")
        self.status_label.setWordWrap(True)
        activity_layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        activity_layout.addWidget(self.progress_bar)
        root.addWidget(activity_card)

        # Executive summary
        summary_card = QFrame()
        summary_card.setObjectName("card")
        summary_layout = QVBoxLayout(summary_card)
        summary_layout.setContentsMargins(20, 16, 20, 18)
        summary_layout.setSpacing(12)

        summary_title = QLabel("Sintesi dell'analisi")
        summary_title.setObjectName("sectionTitle")
        summary_layout.addWidget(summary_title)

        metrics_grid = QGridLayout()
        metrics_grid.setHorizontalSpacing(12)
        metrics_grid.setVerticalSpacing(12)

        self.metric_values = {}
        metric_definitions = [
            ("modules", "MODULI ESEGUITI"),
            ("successful", "MODULI COMPLETATI"),
            ("subdomains", "SOTTODOMINI TROVATI"),
            ("candidates", "DOMINI SIMILI GENERATI"),
            ("ioc", "CORRISPONDENZE IOC"),
            ("image_similarity", "SIMILARITÀ IMMAGINI"),
        ]

        for index, (key, label_text) in enumerate(metric_definitions):
            tile = QFrame()
            tile.setObjectName("metricTile")
            tile_layout = QVBoxLayout(tile)
            tile_layout.setContentsMargins(14, 12, 14, 12)
            tile_layout.setSpacing(5)

            value_label = QLabel("—")
            value_label.setObjectName("metricValue")
            caption_label = QLabel(label_text)
            caption_label.setObjectName("metricCaption")

            tile_layout.addWidget(value_label)
            tile_layout.addWidget(caption_label)
            metrics_grid.addWidget(tile, index // 3, index % 3)
            self.metric_values[key] = value_label

        summary_layout.addLayout(metrics_grid)
        root.addWidget(summary_card)

        # Results
        results_card = QFrame()
        results_card.setObjectName("card")
        results_layout = QVBoxLayout(results_card)
        results_layout.setContentsMargins(20, 16, 20, 18)

        results_header = QHBoxLayout()
        results_title = QLabel("Risultati dell'ultima scansione")
        results_title.setObjectName("sectionTitle")
        results_header.addWidget(results_title)
        results_header.addStretch()

        self.copy_results_button = QPushButton("Copia risultati")
        self.copy_results_button.setObjectName("secondaryButton")
        self.copy_results_button.clicked.connect(self.copy_results)
        results_header.addWidget(self.copy_results_button)
        results_layout.addLayout(results_header)

        self.results_tabs = QTabWidget()
        self.results_tabs.setObjectName("resultsTabs")

        self.overview_table = self._create_results_table(
            ["Modulo", "Esito", "Dettaglio"]
        )
        self.results_tabs.addTab(self.overview_table, "Riepilogo moduli")

        self.domain_details = QTextEdit()
        self.domain_details.setReadOnly(True)
        self.domain_details.setPlaceholderText("Dettagli RDAP e DNS.")
        self.results_tabs.addTab(self.domain_details, "RDAP e DNS")

        self.subdomains_table = self._create_results_table(
            ["Sottodominio", "Stato", "Indirizzi IP", "Fonti"]
        )
        self.results_tabs.addTab(self.subdomains_table, "Sottodomini")

        self.similar_table = self._create_results_table(
            ["Dominio candidato", "Similarità", "Tipo variante", "RDAP"]
        )
        self.results_tabs.addTab(self.similar_table, "Domini simili")

        self.ioc_table = self._create_results_table(
            ["Indicatore", "Tipo", "Fonte", "Confidenza"]
        )
        self.results_tabs.addTab(self.ioc_table, "Threat Intelligence")

        self.risk_details = QTextEdit()
        self.risk_details.setReadOnly(True)
        self.risk_details.setPlaceholderText(
            "La valutazione viene calcolata sulle corrispondenze IOC della scansione."
        )
        self.results_tabs.addTab(self.risk_details, "Valutazione rischio")

        self.images_details = QTextEdit()
        self.images_details.setReadOnly(True)
        self.images_details.setPlaceholderText("Risultati delle analisi immagini.")
        self.results_tabs.addTab(self.images_details, "Immagini")

        self.results_output = QTextEdit()
        self.results_output.setReadOnly(True)
        self.results_output.setMinimumHeight(220)
        self.results_output.setPlaceholderText(
            "Il JSON completo della scansione apparirà qui."
        )
        self.results_tabs.addTab(self.results_output, "JSON completo")

        results_layout.addWidget(self.results_tabs)
        root.addWidget(results_card)

        # History
        history_card = QFrame()
        history_card.setObjectName("card")
        history_layout = QVBoxLayout(history_card)
        history_layout.setContentsMargins(20, 16, 20, 18)

        history_header = QHBoxLayout()
        history_title = QLabel("Cronologia scansioni")
        history_title.setObjectName("sectionTitle")
        history_header.addWidget(history_title)
        history_header.addStretch()

        self.refresh_button = QPushButton("Aggiorna")
        self.refresh_button.setObjectName("secondaryButton")
        self.refresh_button.clicked.connect(self.load_history)
        history_header.addWidget(self.refresh_button)
        history_layout.addLayout(history_header)

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels(
            ["ID scansione", "Dominio", "Stato", "Moduli", "Evidenze"]
        )
        self.history_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.history_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.history_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setMinimumHeight(190)
        self.history_table.cellDoubleClicked.connect(self.show_scan_details)
        history_layout.addWidget(self.history_table)
        root.addWidget(history_card)

        root.addStretch()
        self._apply_styles()

    def _create_module_checkbox(self, title, description, checked, key):
        checkbox = QCheckBox(f"{title}  —  {description}")
        checkbox.setChecked(checked)
        checkbox.setMinimumHeight(30)
        checkbox.setObjectName("moduleCheck")
        return checkbox

    def _module_row(self, checkbox):
        row = QFrame()
        row.setObjectName("moduleRow")
        layout = QHBoxLayout(row)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(8)

        status = QLabel()
        status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status.setMinimumWidth(92)
        status.setObjectName("selectedBadge")

        def update_status(checked):
            status.setText("SELEZIONATO" if checked else "ESCLUSO")
            status.setProperty("selected", checked)
            status.style().unpolish(status)
            status.style().polish(status)

        checkbox.toggled.connect(update_status)
        update_status(checkbox.isChecked())

        layout.addWidget(checkbox, 1)
        layout.addWidget(status)
        return row

    def _apply_styles(self):
        self.setStyleSheet("""
            QMainWindow, QScrollArea, QWidget {
                background-color: #F3F6F9;
                color: #172B3A;
                font-family: "Segoe UI";
                font-size: 10pt;
            }
            QLabel#appTitle {
                color: #087A58;
                font-size: 27pt;
                font-weight: 800;
                letter-spacing: 1px;
            }
            QLabel#appSubtitle {
                color: #718096;
                font-size: 9pt;
                letter-spacing: 1px;
            }
            QLabel#readyBadge {
                background: #E1F4EC;
                color: #087A58;
                border: 1px solid #B8E3D0;
                border-radius: 12px;
                padding: 7px 13px;
                font-weight: bold;
            }
            QFrame#card {
                background: #FFFFFF;
                border: 1px solid #DFE7ED;
                border-radius: 14px;
            }
            QFrame#metricTile {
                background: #F7FAFC;
                border: 1px solid #E3EBF0;
                border-radius: 10px;
            }
            QLabel#metricValue {
                color: #087A58;
                font-size: 22pt;
                font-weight: 800;
            }
            QLabel#metricCaption {
                color: #718096;
                font-size: 7.5pt;
                font-weight: 800;
                letter-spacing: 0.5px;
            }
            QLabel#sectionTitle {
                color: #173447;
                font-size: 16pt;
                font-weight: 700;
            }
            QLabel#subsectionTitle {
                color: #29485B;
                font-size: 11pt;
                font-weight: 700;
                padding-top: 3px;
            }
            QLabel#fieldLabel {
                color: #617789;
                font-size: 8pt;
                font-weight: 700;
                letter-spacing: 1px;
            }
            QLineEdit {
                background: #FAFCFD;
                border: 1px solid #CBD7E0;
                border-radius: 8px;
                padding: 10px 12px;
                color: #172B3A;
                selection-background-color: #16865D;
            }
            QLineEdit:focus {
                border: 2px solid #16865D;
                background: #FFFFFF;
            }
            QGroupBox#moduleGroup {
                background: #F9FBFC;
                border: 1px solid #E0E8EE;
                border-radius: 10px;
                margin-top: 12px;
                padding: 12px 10px 10px 10px;
                color: #587082;
                font-size: 8pt;
                font-weight: 700;
            }
            QGroupBox#moduleGroup::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 5px;
            }
            QFrame#moduleRow {
                background: #FFFFFF;
                border: 1px solid #E5EBF0;
                border-radius: 7px;
            }
            QCheckBox#moduleCheck {
                color: #243B4A;
                spacing: 9px;
                font-size: 9pt;
                font-weight: 600;
            }
            QCheckBox#moduleCheck::indicator {
                width: 19px;
                height: 19px;
                border: 2px solid #93A4B1;
                border-radius: 5px;
                background: #FFFFFF;
            }
            QCheckBox#moduleCheck::indicator:hover {
                border: 2px solid #16865D;
            }
            QCheckBox#moduleCheck::indicator:checked {
                background: #16865D;
                border: 2px solid #16865D;
            }
            QLabel#selectedBadge {
                background: #EDF1F4;
                color: #718096;
                border-radius: 8px;
                padding: 5px 7px;
                font-size: 7pt;
                font-weight: 800;
            }
            QLabel#selectedBadge[selected="true"] {
                background: #DDF3E9;
                color: #087A58;
            }
            QLabel#filePath {
                color: #526B7B;
                background: #F5F8FA;
                border: 1px solid #E5EBF0;
                border-radius: 7px;
                padding: 9px;
            }
            QLabel#hint {
                color: #718096;
                font-size: 8pt;
            }
            QLabel#statusText {
                color: #40596A;
                font-size: 10pt;
            }
            QPushButton {
                border-radius: 8px;
                padding: 9px 14px;
                font-weight: 700;
            }
            QPushButton#primaryButton {
                background: #087A58;
                color: #FFFFFF;
                font-size: 11pt;
                letter-spacing: 1px;
            }
            QPushButton#primaryButton:hover {
                background: #066448;
            }
            QPushButton#primaryButton:disabled {
                background: #A8B9B2;
                color: #F4F7F5;
            }
            QPushButton#secondaryButton {
                background: #E8F1F5;
                color: #24485B;
                border: 1px solid #D5E1E8;
            }
            QPushButton#secondaryButton:hover {
                background: #DCEAF0;
            }
            QPushButton#secondaryButton:disabled {
                background: #EEF1F3;
                color: #A0ABB3;
            }
            QProgressBar {
                border: none;
                border-radius: 5px;
                background: #E8EEF2;
                height: 10px;
                text-align: center;
            }
            QProgressBar::chunk {
                background: #16865D;
                border-radius: 5px;
            }
            QTabWidget::pane {
                border: 1px solid #DCE5EB;
                border-radius: 8px;
                background: #FFFFFF;
                top: -1px;
            }
            QTabBar::tab {
                background: #EAF1F5;
                color: #486273;
                padding: 9px 14px;
                margin-right: 3px;
                border-top-left-radius: 7px;
                border-top-right-radius: 7px;
                font-weight: 700;
            }
            QTabBar::tab:selected {
                background: #087A58;
                color: #FFFFFF;
            }
            QTextEdit, QTableWidget {
                background: #FBFDFE;
                border: 1px solid #DCE5EB;
                border-radius: 8px;
                padding: 7px;
                color: #243B4A;
                selection-background-color: #D5EEE3;
                selection-color: #173447;
            }
            QHeaderView::section {
                background: #EAF1F5;
                color: #365466;
                border: none;
                border-bottom: 1px solid #D7E2E9;
                padding: 9px;
                font-weight: 700;
            }
            QTableWidget::item {
                padding: 6px;
            }
            QTableWidget::item:alternate {
                background: #F4F8FA;
            }
        """)

    def select_image(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Seleziona la prima immagine",
            "",
            "Immagini (*.png *.jpg *.jpeg *.bmp *.webp)",
        )
        if file_path:
            self.image_path = file_path
            self.image_path_label.setText(file_path)

    def select_comparison_image(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Seleziona la seconda immagine",
            "",
            "Immagini (*.png *.jpg *.jpeg *.bmp *.webp)",
        )
        if file_path:
            self.comparison_image_path = file_path
            self.comparison_image_label.setText(file_path)

    def get_selected_modules(self):
        selected = []
        module_checks = (
            (self.domain_scanner_check, "domain_scanner"),
            (self.subdomain_check, "subdomain_finder"),
            (self.similar_domain_check, "similar_domain_analyzer"),
            (self.threat_intel_check, "threat_intel_analyzer"),
            (self.image_hash_check, "image_hash_analyzer"),
            (self.image_similarity_check, "image_similarity_analyzer"),
            (self.logo_detector_check, "logo_detector"),
        )
        for checkbox, module_name in module_checks:
            if checkbox.isChecked():
                selected.append(module_name)
        return selected

    def start_scan(self):
        domain = self.domain_input.text().strip()

        if not domain:
            QMessageBox.warning(
                self, "Dominio mancante",
                "Inserisci un dominio prima di continuare."
            )
            return

        domain_pattern = (
            r"(?=.{1,253}$)"
            r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z]{2,63}"
        )
        if not re.fullmatch(domain_pattern, domain):
            QMessageBox.warning(
                self, "Dominio non valido",
                "Controlla il formato del dominio inserito."
            )
            return

        selected_modules = self.get_selected_modules()
        if not selected_modules:
            QMessageBox.warning(
                self, "Nessun modulo selezionato",
                "Seleziona almeno un modulo da eseguire."
            )
            return

        selected_image_modules = {
            "image_hash_analyzer",
            "image_similarity_analyzer",
            "logo_detector",
        }.intersection(selected_modules)

        if selected_image_modules and not self.image_path:
            QMessageBox.warning(
                self, "Prima immagine mancante",
                "Hai selezionato un modulo immagini. Seleziona la prima immagine."
            )
            return

        if (
            "image_similarity_analyzer" in selected_modules
            and not self.comparison_image_path
        ):
            QMessageBox.warning(
                self, "Seconda immagine mancante",
                "Per confrontare due immagini seleziona anche la seconda."
            )
            return

        if self.scanner_engine is None:
            QMessageBox.critical(
                self, "Errore",
                "Il motore di scansione non è disponibile."
            )
            return

        if self.scan_thread is not None and self.scan_thread.isRunning():
            return

        self.scan_button.setEnabled(False)
        self.header_status.setText("SCANSIONE IN CORSO")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.status_label.setText(f"Scansione passiva in corso: {domain}")
        self.results_output.clear()

        self.scan_thread = QThread(self)
        self.scan_worker = ScanWorker(
            self.scanner_engine,
            domain,
            selected_modules,
            image_path=self.image_path,
            comparison_image_path=self.comparison_image_path,
        )
        self.scan_worker.moveToThread(self.scan_thread)

        self.scan_thread.started.connect(self.scan_worker.run)
        self.scan_worker.completed.connect(self.on_scan_completed)
        self.scan_worker.failed.connect(self.on_scan_failed)
        self.scan_worker.completed.connect(self.scan_thread.quit)
        self.scan_worker.failed.connect(self.scan_thread.quit)
        self.scan_thread.finished.connect(self.scan_worker.deleteLater)
        self.scan_thread.finished.connect(self.on_scan_thread_finished)
        self.scan_thread.finished.connect(self.scan_thread.deleteLater)
        self.scan_thread.start()

    def on_scan_completed(self, result):
        try:
            if self.database_service is None:
                raise RuntimeError("DatabaseService non disponibile.")

            self.database_service.save_scan_result(result)
            self.status_label.setText(
                "Scansione completata e salvata nel database."
            )
            self.header_status.setText("COMPLETATA")
            self._update_scan_summary(result)
            self._populate_structured_results(result)
            self.results_output.setPlainText(self.format_scan_result(result))
            self.load_history()
        except Exception as exc:
            self.status_label.setText(
                "Scansione terminata, ma salvataggio non riuscito."
            )
            self.header_status.setText("ATTENZIONE")
            self.results_output.setPlainText(
                f"Errore durante il salvataggio:\n{exc}\n\n"
                + self.format_scan_result(result)
            )
        finally:
            self.scan_button.setEnabled(True)
            self.progress_bar.setVisible(False)
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(100)

    @staticmethod
    def _create_results_table(headers):
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        table.horizontalHeader().setStretchLastSection(True)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(True)
        table.setMinimumHeight(240)
        return table

    @staticmethod
    def _set_table_rows(table, rows):
        table.setSortingEnabled(False)
        table.setRowCount(len(rows))
        for row_index, values in enumerate(rows):
            for column_index, value in enumerate(values):
                cell = QTableWidgetItem(str(value if value is not None else "—"))
                cell.setToolTip(str(value if value is not None else "—"))
                table.setItem(row_index, column_index, cell)
        table.setSortingEnabled(True)

    def _populate_structured_results(self, result):
        self._set_table_rows(self.overview_table, [])
        self._set_table_rows(self.subdomains_table, [])
        self._set_table_rows(self.similar_table, [])
        self._set_table_rows(self.ioc_table, [])

        self.domain_details.clear()
        self.images_details.clear()
        self.risk_details.clear()

        overview_rows = []
        subdomain_rows = []
        similar_rows = []
        ioc_rows = []
        domain_sections = []
        image_sections = []

        for item in getattr(result, "results", []) or []:
            module_name = getattr(item, "module_name", "modulo")
            success = bool(getattr(item, "success", False))
            data = getattr(item, "data", None)
            error = getattr(item, "error", None)

            if not isinstance(data, dict):
                data = {}

            status_text = "Completato" if success else "Errore"
            detail_text = error or ""

            if module_name == "domain_scanner":
                rdap = data.get("rdap", {}) or {}
                dns = data.get("dns", {}) or {}
                records = dns.get("records", {}) or {}
                domain_sections.append(
                    "DOMAIN SCANNER\n"
                    f"Dominio: {data.get('domain', result.domain)}\n"
                    f"RDAP: {rdap.get('status', 'non disponibile')}\n"
                    f"Registrar: {self._extract_registrar(rdap)}\n"
                    f"Nameserver: {', '.join(rdap.get('nameservers', []) or []) or '—'}\n"
                    f"IP A: {', '.join(records.get('A', []) or []) or '—'}\n"
                    f"IP AAAA: {', '.join(records.get('AAAA', []) or []) or '—'}\n"
                    f"MX: {', '.join(records.get('MX', []) or []) or '—'}\n"
                    f"NS DNS: {', '.join(records.get('NS', []) or []) or '—'}\n"
                    f"TXT: {', '.join(records.get('TXT', []) or []) or '—'}\n"
                    f"TLS: {(data.get('certificate', {}) or {}).get('status', '—')}\n"
                )
                detail_text = f"RDAP: {rdap.get('status', '—')}; record DNS: {len(records)} tipi"

            elif module_name == "subdomain_finder":
                for entry in data.get("subdomains", []) or []:
                    subdomain_rows.append([
                        entry.get("hostname", "—"),
                        entry.get("status", "—"),
                        ", ".join(entry.get("ip_addresses", []) or []),
                        ", ".join(entry.get("sources", []) or []),
                    ])
                source_failures = [
                    f"{source.get('source')}: {source.get('error')}"
                    for source in data.get("sources", []) or []
                    if not source.get("success", False)
                ]
                detail_text = (
                    f"{data.get('total_discovered', len(subdomain_rows))} sottodomini; "
                    f"{len(source_failures)} fonti con errore"
                )
                if source_failures:
                    domain_sections.append(
                        "FONTI SOTTODOMINI\n" + "\n".join(source_failures)
                    )

            elif module_name == "similar_domain_analyzer":
                for entry in data.get("results", []) or []:
                    similar_rows.append([
                        entry.get("domain", "—"),
                        f"{entry.get('similarity_score', '—')}%",
                        entry.get("reason", "—"),
                        entry.get("rdap_status", "—"),
                    ])
                detail_text = (
                    f"{data.get('total_generated', 0)} candidati generati; "
                    f"{data.get('total_analyzed', 0)} analizzati; "
                    f"limite RDAP {data.get('rdap_lookup_limit', '—')}"
                )

            elif module_name == "threat_intel_analyzer":
                for domain_result in data.get("results", []) or []:
                    for match in domain_result.get("matches", []) or []:
                        ioc_rows.append([
                            match.get("indicator", "—"),
                            match.get("type", match.get("indicator_type", "—")),
                            match.get("source", "—"),
                            match.get("confidence", "—"),
                        ])
                detail_text = (
                    f"{data.get('total_matches', 0)} corrispondenze IOC "
                    f"su {data.get('total_analyzed', 0)} indicatori/domini analizzati"
                )

            elif module_name in (
                "image_hash_analyzer",
                "image_similarity_analyzer",
                "logo_detector",
            ):
                image_sections.append(
                    f"{module_name}\n"
                    + json.dumps(data, indent=2, ensure_ascii=False, default=str)
                )
                if module_name == "image_similarity_analyzer":
                    score = (data.get("comparison", {}) or {}).get("similarity_score")
                    detail_text = f"Similarità: {score}%" if score is not None else "Confronto non disponibile"
                elif module_name == "image_hash_analyzer":
                    analysis = data.get("image_analysis", {}) or {}
                    detail_text = f"Immagine: {analysis.get('filename', '—')}"
                else:
                    logo = data.get("logo_analysis", {}) or {}
                    detail_text = (
                        "Possibile logo (euristica)" if logo.get("possible_logo")
                        else "Nessuna parola chiave nel nome file"
                    )

            if isinstance(data, dict) and data.get("skipped"):
                status_text = "Saltato"
                detail_text = data.get("message", detail_text)

            overview_rows.append([module_name, status_text, detail_text or "—"])

        self._set_table_rows(self.overview_table, overview_rows)
        self._set_table_rows(self.subdomains_table, subdomain_rows)
        self._set_table_rows(self.similar_table, similar_rows)
        self._set_table_rows(self.ioc_table, ioc_rows)
        self._populate_risk_assessment(result)

        self.domain_details.setPlainText(
            "\n\n".join(domain_sections) if domain_sections
            else "Nessun dato RDAP/DNS disponibile in questa scansione."
        )
        self.images_details.setPlainText(
            "\n\n".join(image_sections) if image_sections
            else "Nessun modulo immagini eseguito."
        )

    def _populate_risk_assessment(self, result):
        """Render the conservative IOC-based risk indicator for this scan."""
        try:
            assessment = self.risk_scoring_service.calculate(result)
        except Exception as exc:
            self.risk_details.setPlainText(
                "Valutazione non disponibile.\\n"
                f"Errore interno del modulo di scoring: {exc}"
            )
            return

        score = assessment.get("score")
        score_text = f"{score}/100" if score is not None else "Non valutabile"
        level = assessment.get("level", "non_valutabile")
        status = assessment.get("status", "sconosciuto")

        lines = [
            "VALUTAZIONE DEL RISCHIO — INDICATORE BASATO SU IOC",
            "=" * 54,
            f"Dominio: {assessment.get('domain') or getattr(result, 'domain', '—')}",
            f"Indicatore: {assessment.get('label', 'Non valutabile')}",
            f"Punteggio: {score_text}",
            f"Livello: {level.replace('_', ' ').upper()}",
            f"Stato verifica: {status.replace('_', ' ')}",
            "",
            "INTERPRETAZIONE",
            assessment.get("explanation", "Nessuna spiegazione disponibile."),
            "",
            "EVIDENZE",
        ]

        evidence = assessment.get("evidence", []) or []
        if evidence:
            for index, item in enumerate(evidence, start=1):
                lines.extend([
                    f"{index}. {item.get('indicator', '—')}",
                    f"   Tipo: {item.get('indicator_type', '—')}",
                    f"   Dominio associato: {item.get('domain', '—')}",
                    f"   Fonte: {item.get('source', '—')}",
                    f"   Confidenza dichiarata: {item.get('confidence', '—')}/100",
                ])
        else:
            lines.append("Nessuna corrispondenza IOC utilizzabile.")

        warnings = assessment.get("warnings", []) or []
        if warnings:
            lines.extend(["", "AVVERTENZE"])
            lines.extend(f"- {warning}" for warning in warnings)

        method = assessment.get("method", {}) or {}
        lines.extend([
            "",
            "METODO",
            f"Nome: {method.get('name', '—')} (versione {method.get('version', '—')})",
            f"Formula: {method.get('formula', '—')}",
            "",
            "NOTA IMPORTANTE",
            "Questo punteggio è un indicatore basato sulla confidenza delle fonti IOC, "
            "non una probabilità che il dominio sia malevolo. "
            "L'assenza di corrispondenze IOC non dimostra che il dominio sia sicuro. "
            "Somiglianza del nome, DNS, registrazione e TLS non sono usati da soli "
            "come prova di attività malevola.",
        ])
        self.risk_details.setPlainText("\\n".join(lines))

    @staticmethod
    def _extract_registrar(rdap):
        registrar_data = rdap.get("registrar", [])
        try:
            for entry in registrar_data[1]:
                if len(entry) >= 4 and entry[0] == "fn":
                    return entry[3]
        except (IndexError, TypeError):
            pass
        return "—"

    def _update_scan_summary(self, result):
        module_results = getattr(result, "results", []) or []

        total_modules = len(module_results)
        successful_modules = sum(
            1 for item in module_results if getattr(item, "success", False)
        )

        subdomains = 0
        candidates = 0
        ioc_matches = 0
        image_similarity = "—"

        for item in module_results:
            data = getattr(item, "data", None) or {}
            if not isinstance(data, dict):
                continue

            module_name = getattr(item, "module_name", "")

            if module_name == "subdomain_finder":
                subdomains = data.get("total_discovered", len(data.get("subdomains", [])))

            elif module_name == "similar_domain_analyzer":
                candidates = data.get("total_generated", data.get("total_analyzed", 0))

            elif module_name == "threat_intel_analyzer":
                ioc_matches = data.get("total_matches", 0)

            elif module_name == "image_similarity_analyzer":
                comparison = data.get("comparison", {})
                if isinstance(comparison, dict):
                    score = comparison.get("similarity_score")
                    if score is not None:
                        image_similarity = f"{score}%"

        values = {
            "modules": str(total_modules),
            "successful": str(successful_modules),
            "subdomains": str(subdomains),
            "candidates": str(candidates),
            "ioc": str(ioc_matches),
            "image_similarity": image_similarity,
        }

        for key, value in values.items():
            self.metric_values[key].setText(value)

    def on_scan_failed(self, error):
        self.status_label.setText("Scansione non completata.")
        self.header_status.setText("ERRORE")
        self.results_output.setPlainText(error)
        self.scan_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 100)
        QMessageBox.warning(self, "Errore di scansione", error)

    def on_scan_thread_finished(self):
        self.scan_thread = None
        self.scan_worker = None

    def copy_results(self):
        text = self.results_output.toPlainText()
        if not text:
            self.status_label.setText("Non ci sono risultati da copiare.")
            return
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(text)
        self.status_label.setText("Risultati copiati negli appunti.")

    @staticmethod
    def format_scan_result(result):
        lines = [
            f"Dominio: {result.domain}",
            f"Stato: {result.status}",
            f"ID scansione: {result.scan_id}",
            "",
            "RISULTATI MODULI",
            "----------------",
        ]

        for item in result.results:
            lines.append(f"\nModulo: {item.module_name}")
            lines.append(f"Successo: {item.success}")
            if item.error:
                lines.append(f"Errore: {item.error}")
            if item.data is not None:
                lines.append(
                    json.dumps(
                        item.data,
                        indent=2,
                        ensure_ascii=False,
                        default=str,
                    )
                )
        return "\n".join(lines)

    def load_history(self):
        if self.database_service is None:
            return
        try:
            history = self.database_service.get_scan_history()
            self.history_table.setRowCount(len(history))
            for row, item in enumerate(history):
                values = [
                    str(item["scan_id"]),
                    str(item["domain"]),
                    str(item["status"]),
                    str(item["modules_count"]),
                    str(item["findings_count"]),
                ]
                for column, value in enumerate(values):
                    cell = QTableWidgetItem(value)
                    if column == 0:
                        cell.setData(
                            Qt.ItemDataRole.UserRole,
                            item["scan_id"],
                        )
                    self.history_table.setItem(row, column, cell)
        except Exception as exc:
            self.status_label.setText(
                f"Errore caricamento cronologia: {exc}"
            )

    def show_scan_details(self, row, column):
        if self.database_service is None:
            return
        item = self.history_table.item(row, 0)
        if item is None:
            return

        scan_id = item.data(Qt.ItemDataRole.UserRole)
        try:
            details = self.database_service.get_scan_details(scan_id)
            if details is None:
                QMessageBox.information(
                    self, "Dettagli", "Scansione non trovata."
                )
                return

            content = json.dumps(
                details,
                indent=2,
                ensure_ascii=False,
                default=str,
            )
            QMessageBox.information(
                self,
                f"Dettagli: {details['domain']}",
                content[:12000],
            )
        except Exception as exc:
            QMessageBox.warning(
                self,
                "Errore",
                f"Impossibile caricare i dettagli:\n{exc}",
            )

from collections import Counter
from html import escape
import json
import re


class PDFAnonymizationReport:
    """
    Genera informes compactos para usuario final a partir del resultado de:

    - PDFAnonymizer.anonymize_pdf()
    - PDFAnonymizer.anonymize_pdf_directory()

    El informe prioriza:
    - qué páginas o ficheros necesitan revisión;
    - cuántas sustituciones automáticas se han aplicado;
    - qué tipos de datos se han sustituido;
    - qué riesgos o incidencias quedan pendientes.

    Uso con un PDF:
        result = PDFAnonymizer().anonymize_pdf("in.pdf", "out.pdf", people=people)

        report = PDFAnonymizationReport(result)
        report.save_html("informe.html")
        report.save_text("informe.txt")

    Uso con directorio:
        result = PDFAnonymizer().anonymize_pdf_directory("entrada", "salida")

        report = PDFAnonymizationReport(result)
        report.save_directory_html("informe_directorio.html")
        report.save_directory_text("informe_directorio.txt")
    """

    DEFAULT_ENTITY_ORDER = (
        "PERSONA",
        "EMAIL",
        "TELEFONO",
        "DNI_NIE",
        "IBAN",
        "DIRECCION",
        "ROL",
        "IMPORTE",
        "URL",
        "OTRO",
    )

    def __init__(self, pdf_result, entity_order=None):
        if not isinstance(pdf_result, dict):
            raise TypeError(
                "pdf_result debe ser el diccionario devuelto por "
                "anonymize_pdf o anonymize_pdf_directory"
            )

        self.pdf_result = pdf_result
        self.entity_order = tuple(entity_order or self.DEFAULT_ENTITY_ORDER)

    def to_dict(self):
        """
        Devuelve datos agregados de un único PDF.

        Soporta tanto resultados con matches completos como resultados ligeros
        creados con store_matches=False.
        """
        pages = self._build_page_rows()
        totals_by_entity = self._count_total_replacements_by_entity(pages)
        review_pages = [page for page in pages if page["needs_review"]]
        pages_with_replacements = [
            page for page in pages if page["automatic_replacements"] > 0
        ]

        total_pages = len(pages)
        total_replacements = sum(page["automatic_replacements"] for page in pages)
        total_manual_findings = sum(page["manual_findings"] for page in pages)
        llm_errors = [
            {
                "page_number": page["page_number"],
                "llm_error": page["llm_error"],
            }
            for page in pages
            if page.get("llm_error")
        ]

        return {
            "input_path": self.pdf_result.get("input_path"),
            "output_path": self.pdf_result.get("output_path"),
            "total_pages": total_pages,
            "pages_requiring_review": len(review_pages),
            "pages_with_replacements": len(pages_with_replacements),
            "total_automatic_replacements": total_replacements,
            "total_manual_findings": total_manual_findings,
            "manual_review_required": bool(
                self.pdf_result.get("manual_review_required")
            ),
            "llm_errors": llm_errors,
            "replacement_types": totals_by_entity,
            "pages": pages,
        }

    def to_directory_dict(self):
        """
        Devuelve datos agregados de una ejecución de anonymize_pdf_directory().

        El resultado contiene una fila por PDF y, dentro de cada fila, el
        resumen del fichero y sus páginas.
        """
        files = self.pdf_result.get("files", []) or []
        file_rows = []

        for index, file_result in enumerate(files, start=1):
            file_rows.append(self._build_directory_file_row(file_result, index))

        processed_files = [
            file_row for file_row in file_rows
            if file_row["success"] and not file_row["skipped"]
        ]
        failed_files = [
            file_row for file_row in file_rows
            if not file_row["success"] and not file_row["skipped"]
        ]
        skipped_files = [
            file_row for file_row in file_rows
            if file_row["skipped"]
        ]

        totals_by_entity = Counter()
        total_pages = 0
        total_replacements = 0
        total_manual_findings = 0
        files_requiring_review = 0
        files_with_replacements = 0

        for file_row in processed_files:
            totals_by_entity.update(file_row["replacement_types"])
            total_pages += file_row["total_pages"]
            total_replacements += file_row["total_automatic_replacements"]
            total_manual_findings += file_row["total_manual_findings"]

            if file_row["manual_review_required"]:
                files_requiring_review += 1

            if file_row["total_automatic_replacements"] > 0:
                files_with_replacements += 1

        return {
            "input_dir": self.pdf_result.get("input_dir"),
            "output_dir": self.pdf_result.get("output_dir"),
            "recursive": bool(self.pdf_result.get("recursive", False)),
            "total_files": len(file_rows),
            "processed_files": len(processed_files),
            "failed_files": len(failed_files),
            "skipped_files": len(skipped_files),
            "files_requiring_review": files_requiring_review,
            "files_with_replacements": files_with_replacements,
            "total_pages": total_pages,
            "total_automatic_replacements": total_replacements,
            "total_manual_findings": total_manual_findings,
            "manual_review_required": any(
                file_row["manual_review_required"]
                for file_row in processed_files
            ),
            "replacement_types": self._ordered_counter_dict(totals_by_entity),
            "files": file_rows,
        }

    def save_html(self, output_path):
        """
        Guarda un informe HTML autocontenido para un único PDF.
        """
        return self._save_report(output_path, self.to_html())

    def save_text(self, output_path):
        """
        Guarda un informe de texto plano para un único PDF.
        """
        return self._save_report(output_path, self.to_text())

    def save_directory_html(self, output_path):
        """
        Guarda un informe HTML autocontenido para anonymize_pdf_directory().
        """
        return self._save_report(output_path, self.to_directory_html())

    def save_directory_text(self, output_path):
        """
        Guarda un informe de texto plano para anonymize_pdf_directory().
        """
        return self._save_report(output_path, self.to_directory_text())

    def _save_report(self, output_path, content):
        """
        Guarda contenido de informe en disco.

        Lo usan todos los métodos save_* para evitar duplicar la lógica de
        escritura y normalización de ruta.
        """
        output_path = str(output_path)

        with open(output_path, "w", encoding="utf-8") as file:
            file.write(str(content))

        return output_path

    def to_text(self, width=100):
        """
        Devuelve un informe en texto plano de un único PDF.
        """
        data = self.to_dict()
        width = max(int(width or 100), 72)

        lines = []
        lines.append("=" * width)
        lines.append("INFORME DE ANONIMIZACION PDF")
        lines.append("=" * width)
        lines.append(f"PDF original:    {data.get('input_path') or ''}")
        lines.append(f"PDF anonimizado: {data.get('output_path') or ''}")
        lines.append("")

        status = (
            "REVISION NECESARIA"
            if data["manual_review_required"]
            else "SIN REVISION"
        )

        lines.append("RESUMEN")
        lines.append("-" * width)
        lines.append(f"Estado final:                   {status}")
        lines.append(f"Paginas analizadas:             {data['total_pages']}")
        lines.append(f"Sustituciones automaticas:      {data['total_automatic_replacements']}")
        lines.append(f"Paginas con cambios:            {data['pages_with_replacements']}")
        lines.append(f"Paginas que requieren revision: {data['pages_requiring_review']}")
        lines.append(f"Hallazgos pendientes/manuales:  {data['total_manual_findings']}")
        lines.append("")

        lines.extend(self._render_text_replacement_summary(data, width))
        lines.append("")
        lines.extend(self._render_text_page_summary(data, width))

        if data["llm_errors"]:
            lines.append("")
            lines.extend(self._render_text_llm_errors(data, width))

        return "\n".join(lines).rstrip() + "\n"

    def to_directory_text(self, width=120):
        """
        Devuelve un informe en texto plano de anonymize_pdf_directory().
        """
        data = self.to_directory_dict()
        width = max(int(width or 120), 88)

        status = (
            "REVISION NECESARIA"
            if data["manual_review_required"]
            else "SIN REVISION"
        )

        lines = []
        lines.append("=" * width)
        lines.append("INFORME DE ANONIMIZACION POR DIRECTORIO")
        lines.append("=" * width)
        lines.append(f"Directorio original:    {data.get('input_dir') or ''}")
        lines.append(f"Directorio anonimizado: {data.get('output_dir') or ''}")
        lines.append(f"Recursivo:              {data['recursive']}")
        lines.append("")

        lines.append("RESUMEN")
        lines.append("-" * width)
        lines.append(f"Estado final:                    {status}")
        lines.append(f"Ficheros encontrados:            {data['total_files']}")
        lines.append(f"Ficheros procesados:             {data['processed_files']}")
        lines.append(f"Ficheros omitidos:               {data['skipped_files']}")
        lines.append(f"Ficheros con error:              {data['failed_files']}")
        lines.append(f"Ficheros que requieren revision: {data['files_requiring_review']}")
        lines.append(f"Ficheros con sustituciones:      {data['files_with_replacements']}")
        lines.append(f"Paginas analizadas:              {data['total_pages']}")
        lines.append(f"Sustituciones automaticas:       {data['total_automatic_replacements']}")
        lines.append(f"Hallazgos pendientes/manuales:   {data['total_manual_findings']}")
        lines.append("")

        lines.extend(self._render_text_replacement_summary(data, width))
        lines.append("")
        lines.extend(self._render_text_directory_file_summary(data, width))

        return "\n".join(lines).rstrip() + "\n"

    def to_html(self):
        """
        Devuelve un informe HTML compacto para un único PDF.
        """
        data = self.to_dict()

        return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Informe de anonimización PDF</title>
<style>
{self._base_css()}
</style>
</head>
<body>
<main>
  <h1>Informe de anonimización PDF</h1>
  <p>PDF original: <span class="code">{escape(str(data.get("input_path") or ""))}</span></p>
  <p>PDF anonimizado: <span class="code">{escape(str(data.get("output_path") or ""))}</span></p>

  {self._render_kpis(data)}
  {self._render_final_chart(data)}
  {self._render_final_table(data)}
  {self._render_pages_table(data)}
  {self._render_llm_errors(data)}

</main>
</body>
</html>"""

    def to_directory_html(self):
        """
        Devuelve un informe HTML para anonymize_pdf_directory().

        Incluye una tabla con una fila por PDF. Cada fila se puede abrir con
        <details> para ver el resumen del fichero.
        """
        data = self.to_directory_dict()

        return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Informe de anonimización por directorio</title>
<style>
{self._base_css()}
details.file-details {{
  border: 1px solid var(--border);
  border-radius: 12px;
  background: #fff;
}}
details.file-details summary {{
  cursor: pointer;
  list-style: none;
}}
details.file-details summary::-webkit-details-marker {{
  display: none;
}}
.file-summary {{
  display: grid;
  grid-template-columns: 1.4fr 0.8fr 0.7fr 0.8fr 1.2fr 1fr;
  gap: 10px;
  align-items: center;
  padding: 10px 12px;
}}
.file-summary:hover {{
  background: #f9fafb;
}}
.file-details[open] .file-summary {{
  border-bottom: 1px solid var(--border);
}}
.file-detail-body {{
  padding: 14px;
  background: #fff;
}}
.directory-table {{
  display: grid;
  gap: 8px;
}}
.directory-header {{
  display: grid;
  grid-template-columns: 1.4fr 0.8fr 0.7fr 0.8fr 1.2fr 1fr;
  gap: 10px;
  padding: 0 12px 4px;
  color: #374151;
  font-size: 12px;
  font-weight: 700;
}}
.path {{
  word-break: break-all;
}}
.error-box {{
  border: 1px solid #fecaca;
  background: #fef2f2;
  color: var(--bad);
  border-radius: 10px;
  padding: 10px;
  margin-top: 8px;
}}
.subgrid {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 10px;
  margin: 12px 0;
}}
.subcard {{
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 10px;
}}
.subcard strong {{
  display: block;
  font-size: 18px;
}}
@media (max-width: 900px) {{
  .file-summary,
  .directory-header {{
    grid-template-columns: 1fr;
  }}
  .directory-header {{
    display: none;
  }}
  .subgrid {{
    grid-template-columns: repeat(2, 1fr);
  }}
}}
</style>
</head>
<body>
<main>
  <h1>Informe de anonimización por directorio</h1>
  <p>Directorio original: <span class="code">{escape(str(data.get("input_dir") or ""))}</span></p>
  <p>Directorio anonimizado: <span class="code">{escape(str(data.get("output_dir") or ""))}</span></p>

  {self._render_directory_kpis(data)}
  {self._render_final_chart(data)}
  {self._render_final_table(data)}
  {self._render_directory_files_table(data)}

</main>
</body>
</html>"""

    def _build_page_rows(self):
        return self._build_page_rows_from_result(self.pdf_result)

    def _build_page_rows_from_result(self, pdf_result):
        rows = []

        for page in pdf_result.get("pages", []) or []:
            rows.append(self._build_page_row(page, len(rows) + 1))

        return rows

    def _build_page_row(self, page, fallback_page_number):
        matches = page.get("matches")

        if matches is not None:
            matches = matches or []
            auto_matches = [
                match for match in matches
                if match.get("auto_redact", True)
            ]
            manual_matches = [
                match for match in matches
                if match.get("manual_review_required", False)
            ]

            by_entity = Counter(
                str(match.get("entity_type", "OTRO")).upper() or "OTRO"
                for match in auto_matches
            )
            by_source = Counter(
                str(match.get("source", "desconocido"))
                for match in auto_matches
            )

            automatic_replacements = len(auto_matches)
            manual_findings = len(manual_matches)
            replacement_types = self._ordered_counter_dict(by_entity)
            replacement_sources = dict(sorted(by_source.items()))

        else:
            automatic_replacements = int(
                page.get("automatic_replacements_count", 0) or 0
            )
            manual_findings = int(
                page.get("manual_review_matches_count", 0) or 0
            )
            replacement_types = self._ordered_counter_dict(
                Counter(page.get("replacement_types", {}) or {})
            )
            replacement_sources = {}

        return {
            "page_number": int(page.get("page_number", fallback_page_number)),
            "needs_review": bool(page.get("manual_review_required")),
            "automatic_replacements": automatic_replacements,
            "manual_findings": manual_findings,
            "replacement_types": replacement_types,
            "replacement_sources": replacement_sources,
            "llm_detection_skipped": bool(page.get("llm_detection_skipped", False)),
            "llm_error": page.get("llm_error"),
        }

    def _build_directory_file_row(self, file_result, index):
        success = bool(file_result.get("success", False))
        skipped = bool(file_result.get("skipped", False))
        error = file_result.get("error")
        pages = self._build_page_rows_from_result(file_result)
        replacement_types = self._count_total_replacements_by_entity(pages)

        total_pages = len(pages)
        total_automatic_replacements = sum(
            page["automatic_replacements"]
            for page in pages
        )
        total_manual_findings = sum(
            page["manual_findings"]
            for page in pages
        )
        pages_requiring_review = sum(
            1
            for page in pages
            if page["needs_review"]
        )
        pages_with_replacements = sum(
            1
            for page in pages
            if page["automatic_replacements"] > 0
        )

        llm_errors = [
            {
                "page_number": page["page_number"],
                "llm_error": page["llm_error"],
            }
            for page in pages
            if page.get("llm_error")
        ]

        return {
            "index": index,
            "input_path": file_result.get("input_path"),
            "output_path": file_result.get("output_path"),
            "success": success,
            "skipped": skipped,
            "error": error,
            "manual_review_required": bool(
                file_result.get("manual_review_required", False)
            ),
            "total_pages": total_pages,
            "pages_requiring_review": pages_requiring_review,
            "pages_with_replacements": pages_with_replacements,
            "total_automatic_replacements": total_automatic_replacements,
            "total_manual_findings": total_manual_findings,
            "replacement_types": replacement_types,
            "llm_errors": llm_errors,
            "pages": pages,
        }

    def _count_total_replacements_by_entity(self, pages):
        totals = Counter()

        for page in pages:
            totals.update(page["replacement_types"])

        return self._ordered_counter_dict(totals)

    def _ordered_counter_dict(self, counter):
        result = {}

        for entity_type in self.entity_order:
            if counter.get(entity_type, 0):
                result[entity_type] = int(counter[entity_type])

        for entity_type, count in sorted(counter.items()):
            if entity_type not in result and count:
                result[entity_type] = int(count)

        return result

    def _format_llm_status(self, page):
        """
        Devuelve el texto corto de estado LLM para una página.

        - Si hay error: "LLM error" o "LLM error 400" si se puede extraer código.
        - Si se omitió sin error: "LLM no ejecutado".
        - Si no hay incidencia: None.
        """
        llm_error = page.get("llm_error")

        if llm_error:
            error_code = self._extract_error_code(llm_error)

            if error_code:
                return f"LLM error {error_code}"

            return "LLM error"

        if page.get("llm_detection_skipped"):
            return "LLM no ejecutado"

        return None

    def _extract_error_code(self, error):
        """
        Intenta extraer un código de error útil desde diferentes formatos:

        - "Error code: 400"
        - "status_code=400"
        - "HTTP 429"
        - "{'status_code': 500}"
        - objetos/errores con atributo status_code o code
        """
        for attr in ("status_code", "code"):
            value = getattr(error, attr, None)

            if isinstance(value, int):
                return str(value)

            if isinstance(value, str) and value.strip().isdigit():
                return value.strip()

        error_text = str(error or "")

        patterns = (
            r"\bstatus[_\s-]?code['\"]?\s*[:=]\s*['\"]?(\d{3})\b",
            r"\berror[_\s-]?code['\"]?\s*[:=]\s*['\"]?(\d{3})\b",
            r"\bHTTP\s+(\d{3})\b",
            r"\bstatus\s+(\d{3})\b",
            r"\bcode\s*[:=]\s*['\"]?(\d{3})\b",
        )

        for pattern in patterns:
            match = re.search(pattern, error_text, flags=re.IGNORECASE)

            if match:
                return match.group(1)

        return None

    def _render_kpis(self, data):
        review_class = "bad" if data["manual_review_required"] else "ok"
        review_text = (
            "Revisión necesaria"
            if data["manual_review_required"]
            else "Sin revisión"
        )

        return f"""
<section class="grid">
  <div class="card"><strong>{data["total_pages"]}</strong><span>Páginas analizadas</span></div>
  <div class="card"><strong>{data["total_automatic_replacements"]}</strong><span>Sustituciones automáticas</span></div>
  <div class="card"><strong>{data["pages_with_replacements"]}</strong><span>Páginas con cambios</span></div>
  <div class="card"><strong>{data["pages_requiring_review"]}</strong><span>Páginas a revisar</span></div>
  <div class="card"><strong><span class="status {review_class}">{review_text}</span></strong><span>Estado final</span></div>
</section>"""

    def _render_directory_kpis(self, data):
        review_class = "bad" if data["manual_review_required"] else "ok"
        review_text = (
            "Revisión necesaria"
            if data["manual_review_required"]
            else "Sin revisión"
        )

        return f"""
<section class="grid">
  <div class="card"><strong>{data["total_files"]}</strong><span>PDFs encontrados</span></div>
  <div class="card"><strong>{data["processed_files"]}</strong><span>PDFs procesados</span></div>
  <div class="card"><strong>{data["failed_files"]}</strong><span>PDFs con error</span></div>
  <div class="card"><strong>{data["total_automatic_replacements"]}</strong><span>Sustituciones automáticas</span></div>
  <div class="card"><strong><span class="status {review_class}">{review_text}</span></strong><span>Estado final</span></div>
</section>"""

    def _render_final_chart(self, data):
        counts = data["replacement_types"]

        return f"""
<section>
  <h2>Gráfica final de sustituciones</h2>
  {self._render_stacked_bar(counts)}
</section>"""

    def _render_final_table(self, data):
        counts = data["replacement_types"]

        if not counts:
            rows = (
                '<tr><td colspan="3" class="small">'
                "No se han aplicado sustituciones automáticas."
                "</td></tr>"
            )
        else:
            total = sum(counts.values())
            rows = "\n".join(
                f"<tr><td>{escape(entity_type)}</td><td>{count}</td>"
                f"<td>{self._percent(count, total)}</td></tr>"
                for entity_type, count in counts.items()
            )

        return f"""
<section>
  <h2>Tabla resumen final</h2>
  <table>
    <thead>
      <tr><th>Tipo</th><th>Sustituciones</th><th>% del total</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</section>"""

    def _render_pages_table(self, data):
        if not data["pages"]:
            rows = (
                '<tr><td colspan="6" class="small">'
                "No hay páginas analizadas."
                "</td></tr>"
            )
        else:
            rows = "\n".join(self._render_page_row(page) for page in data["pages"])

        return f"""
<section>
  <h2>Resumen por página</h2>
  <table>
    <thead>
      <tr>
        <th>Página</th>
        <th>Estado</th>
        <th>Sustituciones</th>
        <th>Tipos</th>
        <th>Distribución</th>
        <th>Pendiente</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</section>"""

    def _render_page_row(self, page):
        status_class = "warn" if page["needs_review"] else "ok"
        status_text = "Revisar" if page["needs_review"] else "OK"
        pending_parts = []

        if page["manual_findings"]:
            pending_parts.append(f'{page["manual_findings"]} hallazgo(s) manual(es)')

        llm_status = self._format_llm_status(page)

        if llm_status:
            pending_parts.append(llm_status)

        if not pending_parts:
            pending_parts.append("—")

        types_text = self._format_counts(page["replacement_types"])

        return f"""
<tr>
  <td>{page["page_number"]}</td>
  <td><span class="status {status_class}">{status_text}</span></td>
  <td>{page["automatic_replacements"]}</td>
  <td>{escape(types_text)}</td>
  <td>{self._render_stacked_bar(page["replacement_types"], compact=True)}</td>
  <td>{escape(", ".join(pending_parts))}</td>
</tr>"""

    def _render_directory_files_table(self, data):
        if not data["files"]:
            rows = '<p class="small">No hay ficheros PDF en el resultado.</p>'
        else:
            rows = "\n".join(
                self._render_directory_file_detail(file_row)
                for file_row in data["files"]
            )

        return f"""
<section>
  <h2>PDFs procesados</h2>
  <div class="directory-table">
    <div class="directory-header">
      <div>Fichero</div>
      <div>Estado</div>
      <div>Páginas</div>
      <div>Sustituciones</div>
      <div>Tipos</div>
      <div>Distribución</div>
    </div>
    {rows}
  </div>
</section>"""

    def _render_directory_file_detail(self, file_row):
        status_class, status_text = self._file_status(file_row)
        types_text = self._format_counts(file_row["replacement_types"])
        details_html = self._render_directory_file_inner_summary(file_row)

        return f"""
<details class="file-details">
  <summary>
    <div class="file-summary">
      <div class="path code">{escape(str(file_row.get("input_path") or ""))}</div>
      <div><span class="status {status_class}">{escape(status_text)}</span></div>
      <div>{file_row["total_pages"]}</div>
      <div>{file_row["total_automatic_replacements"]}</div>
      <div>{escape(types_text)}</div>
      <div>{self._render_stacked_bar(file_row["replacement_types"], compact=True)}</div>
    </div>
  </summary>
  <div class="file-detail-body">
    {details_html}
  </div>
</details>"""

    def _render_directory_file_inner_summary(self, file_row):
        if file_row["skipped"]:
            return (
                '<p class="small">'
                "Fichero omitido. No se generó resumen de páginas."
                "</p>"
            )

        if not file_row["success"]:
            return f"""
<p>Salida prevista: <span class="code">{escape(str(file_row.get("output_path") or ""))}</span></p>
<div class="error-box">{escape(str(file_row.get("error") or "Error desconocido"))}</div>"""

        data = {
            "total_pages": file_row["total_pages"],
            "total_automatic_replacements": file_row["total_automatic_replacements"],
            "pages_with_replacements": file_row["pages_with_replacements"],
            "pages_requiring_review": file_row["pages_requiring_review"],
            "total_manual_findings": file_row["total_manual_findings"],
            "manual_review_required": file_row["manual_review_required"],
            "replacement_types": file_row["replacement_types"],
            "pages": file_row["pages"],
            "llm_errors": file_row["llm_errors"],
        }

        return f"""
<p>PDF anonimizado: <span class="code">{escape(str(file_row.get("output_path") or ""))}</span></p>
<div class="subgrid">
  <div class="subcard"><strong>{file_row["total_pages"]}</strong><span class="small">Páginas</span></div>
  <div class="subcard"><strong>{file_row["total_automatic_replacements"]}</strong><span class="small">Sustituciones</span></div>
  <div class="subcard"><strong>{file_row["pages_requiring_review"]}</strong><span class="small">Páginas a revisar</span></div>
  <div class="subcard"><strong>{file_row["total_manual_findings"]}</strong><span class="small">Hallazgos manuales</span></div>
</div>
{self._render_final_table(data)}
{self._render_pages_table(data)}
{self._render_llm_errors(data)}"""

    def _render_llm_errors(self, data):
        if not data["llm_errors"]:
            return ""

        rows = "\n".join(
            f"<tr><td>{item['page_number']}</td>"
            f"<td>{escape(str(item['llm_error']))}</td></tr>"
            for item in data["llm_errors"]
        )

        return f"""
<section>
  <h2>Incidencias de detección LLM</h2>
  <table>
    <thead><tr><th>Página</th><th>Error</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>"""

    def _render_text_replacement_summary(self, data, width):
        lines = []
        counts = data["replacement_types"]

        lines.append("SUSTITUCIONES POR TIPO")
        lines.append("-" * width)

        if not counts:
            lines.append("No se han aplicado sustituciones automaticas.")
            return lines

        total = sum(counts.values())
        max_label_len = max(len(entity_type) for entity_type in counts)
        max_count = max(counts.values())

        for entity_type, count in counts.items():
            percent = self._percent(count, total)
            bar = self._text_bar(count, max_count, size=24)
            lines.append(
                f"{entity_type:<{max_label_len}}  {count:>5}  {percent:>6}  {bar}"
            )

        return lines

    def _render_text_page_summary(self, data, width):
        lines = []
        pages = data["pages"]

        lines.append("RESUMEN POR PAGINA")
        lines.append("-" * width)

        if not pages:
            lines.append("No hay paginas analizadas.")
            return lines

        header = (
            f"{'Pag.':>4}  {'Estado':<10}  {'Sust.':>6}  "
            f"{'Pend.':>6}  Tipos"
        )
        lines.append(header)
        lines.append("-" * min(width, len(header) + 48))

        for page in pages:
            status = "REVISAR" if page["needs_review"] else "OK"
            types_text = self._format_counts(page["replacement_types"])

            llm_status = self._format_llm_status(page)

            if llm_status:
                if types_text == "—":
                    types_text = llm_status
                else:
                    types_text = f"{types_text}; {llm_status}"

            lines.append(
                f"{page['page_number']:>4}  "
                f"{status:<10}  "
                f"{page['automatic_replacements']:>6}  "
                f"{page['manual_findings']:>6}  "
                f"{types_text}"
            )

        return lines

    def _render_text_directory_file_summary(self, data, width):
        lines = []
        files = data["files"]

        lines.append("RESUMEN POR FICHERO")
        lines.append("-" * width)

        if not files:
            lines.append("No hay ficheros PDF en el resultado.")
            return lines

        header = (
            f"{'#':>3}  {'Estado':<10}  {'Pag.':>5}  {'Sust.':>6}  "
            f"{'Pend.':>6}  Fichero / tipos"
        )
        lines.append(header)
        lines.append("-" * min(width, len(header) + 72))

        for file_row in files:
            _, status = self._file_status(file_row)
            file_path = str(file_row.get("input_path") or "")
            types_text = self._format_counts(file_row["replacement_types"])

            if file_row["error"]:
                types_text = f"ERROR: {file_row['error']}"
            elif file_row["skipped"]:
                types_text = "OMITIDO"

            lines.append(
                f"{file_row['index']:>3}  "
                f"{status:<10}  "
                f"{file_row['total_pages']:>5}  "
                f"{file_row['total_automatic_replacements']:>6}  "
                f"{file_row['total_manual_findings']:>6}  "
                f"{file_path}"
            )
            lines.append(f"{'':>37}  {types_text}")

            if file_row["success"] and file_row["pages"]:
                for page in file_row["pages"]:
                    page_status = "REVISAR" if page["needs_review"] else "OK"
                    page_types = self._format_counts(page["replacement_types"])

                    llm_status = self._format_llm_status(page)

                    if llm_status:
                        page_types = (
                            llm_status
                            if page_types == "—"
                            else f"{page_types}; {llm_status}"
                        )

                    lines.append(
                        f"{'':>5} Pag. {page['page_number']:>4}  "
                        f"{page_status:<8}  "
                        f"sust. {page['automatic_replacements']:>4}  "
                        f"pend. {page['manual_findings']:>4}  "
                        f"{page_types}"
                    )

            lines.append("")

        return lines

    def _render_text_llm_errors(self, data, width):
        lines = []

        lines.append("INCIDENCIAS DE DETECCION LLM")
        lines.append("-" * width)

        for item in data["llm_errors"]:
            error = str(item.get("llm_error") or "").strip()
            lines.append(f"Pagina {item['page_number']}: {error}")

        return lines

    def _render_stacked_bar(self, counts, compact=False):
        if not counts:
            return '<span class="small">Sin sustituciones</span>'

        total = sum(counts.values())
        colors = self._entity_colors()
        segments = []

        for entity_type, count in counts.items():
            width = max((count / total) * 100, 2)
            color = colors.get(entity_type, "#9ca3af")
            title = escape(f"{entity_type}: {count}")

            segments.append(
                f'<span class="segment" title="{title}" '
                f'style="width:{width:.2f}%; background:{color};"></span>'
            )

        bar = f'<div class="bar">{"".join(segments)}</div>'

        if compact:
            return bar

        legend = "".join(
            f'<span><span class="dot" style="background:{colors.get(entity_type, "#9ca3af")}"></span>'
            f'{escape(entity_type)}: {count}</span>'
            for entity_type, count in counts.items()
        )

        return f'{bar}<div class="legend">{legend}</div>'

    def _text_bar(self, value, max_value, size=24):
        if not value or not max_value:
            return ""

        filled = max(1, round((value / max_value) * size))
        empty = max(size - filled, 0)

        return "[" + ("#" * filled) + ("." * empty) + "]"

    def _file_status(self, file_row):
        if file_row["skipped"]:
            return "warn", "Omitido"

        if not file_row["success"]:
            return "bad", "Error"

        if file_row["manual_review_required"]:
            return "warn", "Revisar"

        return "ok", "OK"

    def _entity_colors(self):
        return {
            "PERSONA": "#2563eb",
            "EMAIL": "#7c3aed",
            "TELEFONO": "#0891b2",
            "DNI_NIE": "#dc2626",
            "IBAN": "#ea580c",
            "DIRECCION": "#16a34a",
            "ROL": "#4f46e5",
            "IMPORTE": "#ca8a04",
            "URL": "#64748b",
            "OTRO": "#111827",
        }

    def _format_counts(self, counts):
        if not counts:
            return "—"

        return ", ".join(
            f"{entity_type}: {count}"
            for entity_type, count in counts.items()
        )

    def _percent(self, count, total):
        if not total:
            return "0%"

        return f"{(count / total) * 100:.1f}%"

    def _base_css(self):
        return """
:root {
  --border: #e5e7eb;
  --text: #111827;
  --muted: #6b7280;
  --bg: #f9fafb;
  --ok: #15803d;
  --warn: #b45309;
  --bad: #b91c1c;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 24px;
  font-family: Arial, Helvetica, sans-serif;
  color: var(--text);
  background: var(--bg);
}
main {
  max-width: 1120px;
  margin: 0 auto;
  background: white;
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 24px;
}
h1 { margin: 0 0 6px; font-size: 24px; }
h2 { margin: 28px 0 12px; font-size: 17px; }
h3 { margin: 18px 0 8px; font-size: 14px; }
p { margin: 4px 0; color: var(--muted); }
.grid {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 12px;
  margin-top: 18px;
}
.card {
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 14px;
  background: #fff;
}
.card strong {
  display: block;
  font-size: 24px;
  margin-bottom: 4px;
}
.card span {
  color: var(--muted);
  font-size: 12px;
}
.status {
  display: inline-block;
  padding: 4px 8px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
}
.status.ok { color: var(--ok); background: #dcfce7; }
.status.warn { color: var(--warn); background: #fef3c7; }
.status.bad { color: var(--bad); background: #fee2e2; }
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
th, td {
  padding: 9px 8px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  vertical-align: top;
}
th {
  color: #374151;
  background: #f3f4f6;
  font-size: 12px;
}
.bar {
  display: flex;
  height: 22px;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: #f3f4f6;
  min-width: 150px;
}
.segment {
  display: inline-block;
  height: 100%;
}
.legend {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 14px;
  margin-top: 10px;
  font-size: 12px;
  color: var(--muted);
}
.dot {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 99px;
  margin-right: 4px;
}
.small { color: var(--muted); font-size: 12px; }
.code {
  font-family: monospace;
  font-size: 12px;
}
@media (max-width: 900px) {
  .grid { grid-template-columns: repeat(2, 1fr); }
}
"""


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("result_json")
    parser.add_argument("output_path")
    parser.add_argument(
        "--format",
        choices=("html", "text", "directory-html", "directory-text"),
        default=None,
        help="Formato de salida. Si se omite, se infiere por la extension y por el JSON."
    )
    args = parser.parse_args()

    with open(args.result_json, "r", encoding="utf-8") as file:
        pdf_result = json.load(file)

    report = PDFAnonymizationReport(pdf_result)
    output_format = args.format

    if output_format is None:
        is_directory_result = "files" in pdf_result
        wants_html = args.output_path.lower().endswith(".html")

        if is_directory_result:
            output_format = "directory-html" if wants_html else "directory-text"
        else:
            output_format = "html" if wants_html else "text"

    if output_format == "html":
        report.save_html(args.output_path)
    elif output_format == "text":
        report.save_text(args.output_path)
    elif output_format == "directory-html":
        report.save_directory_html(args.output_path)
    else:
        report.save_directory_text(args.output_path)

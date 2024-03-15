using iTextSharp.text;
using iTextSharp.text.pdf;
using OfficeOpenXml;
using OfficeOpenXml.Style;
using PizzeriaImpulsMVC.Application.Interfaces;
using PizzeriaImpulsMVC.Application.ViewModels.Report;
using PizzeriaImpulsMVC.Domain.Interfaces;
using Document = iTextSharp.text.Document;

namespace PizzeriaImpulsMVC.Application.Services
{

    public class ReportService : IReportService
    {
        private readonly IReportRepository _reportRepository;

        public ReportService(IReportRepository reportRepository)
        {
            _reportRepository = reportRepository;
        }

        public ListGeneratedSalesReportVm GenerateSalesReport(DateTime datefrom, DateTime dateTo)
        {
            var generatedSalesReport = _reportRepository.GenerateSalesReport(datefrom, dateTo);

            var rowList = new List<GeneratedSalesReportVm>();

            foreach (var item in generatedSalesReport)
            {
                var row = new GeneratedSalesReportVm()
                {
                    OrderDate = item.OrderDate,
                    UserName = item.UserName,
                    TotalPrice = item.Total
                };

                rowList.Add(row);
            }

            var generatedSalesReportVm = new ListGeneratedSalesReportVm()
            {
                Rows = rowList
            };

            return generatedSalesReportVm;
        }

        public byte[] GeneratePDF(DateTime dateFrom, DateTime dateTo)
        {
            var reportData = GenerateSalesReport(dateFrom, dateTo);

            using (MemoryStream memoryStream = new MemoryStream())
            {
                Document document = new Document(PageSize.A4, 25, 25, 30, 30);
                PdfWriter pdfWriter = PdfWriter.GetInstance(document, memoryStream);
                document.Open();

                Paragraph titleParagraph = new Paragraph($"Sales report from {dateFrom} to {dateTo} generated from PizzeriaImpulsMVC Web Application",
                                                            new Font(Font.FontFamily.COURIER, 15));
                
                document.Add(titleParagraph);

                Paragraph brakeParagraph = new Paragraph("   ", new Font(Font.FontFamily.COURIER, 15));
                document.Add(brakeParagraph);

                PdfPTable tableWithReportData = new PdfPTable(3);

                PdfPCell pdfDateCell = new PdfPCell(new Phrase("Date", new Font(Font.FontFamily.COURIER, 10)));
                pdfDateCell.BackgroundColor = BaseColor.LIGHT_GRAY;
                pdfDateCell.Border = iTextSharp.text.Rectangle.BOTTOM_BORDER | iTextSharp.text.Rectangle.TOP_BORDER | iTextSharp.text.Rectangle.LEFT_BORDER | iTextSharp.text.Rectangle.RIGHT_BORDER;
                pdfDateCell.BorderWidthBottom = 1f;
                pdfDateCell.BorderWidthTop = 1f;
                pdfDateCell.BorderWidthLeft = 1f;
                pdfDateCell.BorderWidthRight = 1f;
                pdfDateCell.HorizontalAlignment = Element.ALIGN_CENTER;
                pdfDateCell.VerticalAlignment = Element.ALIGN_CENTER;
                tableWithReportData.AddCell(pdfDateCell);

                PdfPCell pdfUserNameCell = new PdfPCell(new Phrase("UserName", new Font(Font.FontFamily.COURIER, 10)));
                pdfUserNameCell.BackgroundColor = BaseColor.LIGHT_GRAY;
                pdfUserNameCell.Border = iTextSharp.text.Rectangle.BOTTOM_BORDER | iTextSharp.text.Rectangle.TOP_BORDER | iTextSharp.text.Rectangle.LEFT_BORDER | iTextSharp.text.Rectangle.RIGHT_BORDER;
                pdfUserNameCell.BorderWidthBottom = 1f;
                pdfUserNameCell.BorderWidthTop = 1f;
                pdfUserNameCell.BorderWidthLeft = 1f;
                pdfUserNameCell.BorderWidthRight = 1f;
                pdfUserNameCell.HorizontalAlignment = Element.ALIGN_CENTER;
                pdfUserNameCell.VerticalAlignment = Element.ALIGN_CENTER;
                tableWithReportData.AddCell(pdfUserNameCell);

                PdfPCell pdfPriceCell = new PdfPCell(new Phrase("Price[$]", new Font(Font.FontFamily.COURIER, 10)));
                pdfPriceCell.BackgroundColor = BaseColor.LIGHT_GRAY;
                pdfPriceCell.Border = iTextSharp.text.Rectangle.BOTTOM_BORDER | iTextSharp.text.Rectangle.TOP_BORDER | iTextSharp.text.Rectangle.LEFT_BORDER | iTextSharp.text.Rectangle.RIGHT_BORDER;
                pdfPriceCell.BorderWidthBottom = 1f;
                pdfPriceCell.BorderWidthTop = 1f;
                pdfPriceCell.BorderWidthLeft = 1f;
                pdfPriceCell.BorderWidthRight = 1f;
                pdfPriceCell.HorizontalAlignment = Element.ALIGN_CENTER;
                pdfPriceCell.VerticalAlignment = Element.ALIGN_CENTER;
                tableWithReportData.AddCell(pdfPriceCell);

                for (int i = 0; i < reportData.Rows.Count; i++)
                {
                    PdfPCell pdfDateCellWithData = new PdfPCell(new Phrase(reportData.Rows[i].OrderDate.ToString()));
                    PdfPCell pdfUserNameCellWithData = new PdfPCell(new Phrase(reportData.Rows[i].UserName));
                    PdfPCell pdfPriceCellWithData = new PdfPCell(new Phrase(reportData.Rows[i].TotalPrice.ToString()));

                    pdfDateCellWithData.HorizontalAlignment = Element.ALIGN_CENTER;
                    pdfUserNameCellWithData.HorizontalAlignment = Element.ALIGN_CENTER;
                    pdfPriceCellWithData.HorizontalAlignment = Element.ALIGN_CENTER;

                    tableWithReportData.AddCell(pdfDateCellWithData);
                    tableWithReportData.AddCell(pdfUserNameCellWithData);
                    tableWithReportData.AddCell(pdfPriceCellWithData);
                }

                document.Add(tableWithReportData);
                document.Close();
                pdfWriter.Close();

                var memoryS = memoryStream.ToArray();

                return memoryS;
            }
        }

        
        public string GenerateCSV(DateTime dateFrom, DateTime dateTo)
        {
            var reportData = GenerateSalesReport(dateFrom, dateTo);

            var header = "date, userName, price";

            var path = $"../PizzeriaImpulsMVC.Web/Reports/CSVs/SalesReport{DateTime.Now.Year}_{DateTime.Now.Month}_{DateTime.Now.Day}" +
                $"{DateTime.Now.Hour}_{DateTime.Now.Minute}.csv";

            using (StreamWriter sw = new StreamWriter(path))
            {
                sw.WriteLine(header);

                foreach (var row in reportData.Rows)
                {
                    sw.WriteLine(row.OrderDate.ToString().Replace(' ', '_') + "," + row.UserName + "," + (row.TotalPrice.ToString().Replace(',', '.')));
                }
            }

            return path;
        }

        public string GenerateXLSX(DateTime dateFrom, DateTime dateTo)
        {
            var reportData = GenerateSalesReport(dateFrom, dateTo);

            ExcelPackage excelFile = new ExcelPackage();

            var workSheet = excelFile.Workbook.Worksheets.Add("Sales report");

            workSheet.TabColor = System.Drawing.Color.Black;
            workSheet.DefaultRowHeight = 12;

            workSheet.Row(1).Height = 20;
            workSheet.Row(1).Style.HorizontalAlignment = ExcelHorizontalAlignment.Center;
            workSheet.Row(1).Style.Font.Bold = true;

            workSheet.Cells[1, 1].Value = "Date";
            workSheet.Cells[1, 2].Value = "UserName";
            workSheet.Cells[1, 3].Value = "Price [$]";

            var recordIndex = 2;

            foreach (var row in reportData.Rows)
            {
                workSheet.Cells[recordIndex, 1].Value = row.OrderDate.ToString();
                workSheet.Cells[recordIndex, 2].Value = row.UserName;
                workSheet.Cells[recordIndex, 3].Value = row.TotalPrice;
                recordIndex++;
            }

            workSheet.Column(1).AutoFit();
            workSheet.Column(2).AutoFit();
            workSheet.Column(3).AutoFit();

            var path = $"../PizzeriaImpulsMVC.Web/Reports/XLSXs/SalesReport{DateTime.Now.Year}_{DateTime.Now.Month}_{DateTime.Now.Day}" +
                $"{DateTime.Now.Hour}_{DateTime.Now.Minute}.xlsx";

            FileStream objFileStrm = File.Create(path);
            objFileStrm.Close();

            File.WriteAllBytes(path, excelFile.GetAsByteArray());
            excelFile.Dispose();

            return path;
        }
    }
}

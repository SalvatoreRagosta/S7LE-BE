using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PizzeriaImpulsMVC.Application.Interfaces;
using PizzeriaImpulsMVC.Application.ViewModels.Report;
using System.Data;

namespace PizzeriaImpulsMVC.Web.Controllers
{
    public class ReportController : Controller
    {
        private readonly IReportService _reportService;

        public ReportController(IReportService reportService)
        {
            _reportService = reportService;
        }

        [HttpGet]
        [Authorize(Roles = "Manager")]
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        [Authorize(Roles = "Manager")]
        public IActionResult GeneratedSalesReport(GenerateSalesReportVm generateSalesReportVm)
        {
            var generatedReport = _reportService.GenerateSalesReport(generateSalesReportVm.DateFrom, generateSalesReportVm.DateTo);
            var test = generatedReport.Rows.Select(r => r.OrderDate).Min();

            return View(generatedReport);
        }

        
        [Authorize(Roles = "Manager")]
        public IActionResult GeneratePDF(DateTime dateFrom, DateTime dateTo)
        {
            var ms = _reportService.GeneratePDF(dateFrom, dateTo);
            var fileName = $"SalesReport{DateTime.Now.Year}_{DateTime.Now.Month}_{DateTime.Now.Day}_" +
                $"{DateTime.Now.Hour}_{DateTime.Now.Minute}.pdf";

            return File(ms, "application/vnd", fileName);

        }

        [Authorize(Roles = "Manager")]
        public IActionResult GenerateCSV(DateTime dateFrom, DateTime dateTo)
        {
            var path = _reportService.GenerateCSV(dateFrom, dateTo);
            var fileName = $"SalesReport{DateTime.Now.Year}_{DateTime.Now.Month}_{DateTime.Now.Day}_" +
                $"{DateTime.Now.Hour}_{DateTime.Now.Minute}.csv";
            byte[] fileBytes = System.IO.File.ReadAllBytes(path);

            return File(fileBytes, System.Net.Mime.MediaTypeNames.Application.Octet, fileName);
        }

        [Authorize(Roles = "Manager")]
        public IActionResult GenerateXLSX(DateTime dateFrom, DateTime dateTo)
        {
            var path = _reportService.GenerateXLSX(dateFrom, dateTo);
            var fileName = $"SalesReport{DateTime.Now.Year}_{DateTime.Now.Month}_{DateTime.Now.Day}_" +
                $"{DateTime.Now.Hour}_{DateTime.Now.Minute}.xlsx";
            byte[] fileBytes = System.IO.File.ReadAllBytes(path);

            return File(fileBytes, System.Net.Mime.MediaTypeNames.Application.Octet, fileName);
        }
    }
}

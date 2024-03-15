using PizzeriaImpulsMVC.Application.ViewModels.Report;

namespace PizzeriaImpulsMVC.Application.Interfaces
{
    public interface IReportService
    {
        ListGeneratedSalesReportVm GenerateSalesReport(DateTime datefrom, DateTime dateTo);
        byte[] GeneratePDF(DateTime dateFrom, DateTime dateTo);
        string GenerateCSV(DateTime dateFrom, DateTime dateTo);
        string GenerateXLSX(DateTime dateFrom, DateTime dateTo);
    }
}

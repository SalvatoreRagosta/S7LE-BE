using PizzeriaImpulsMVC.Domain.Models;

namespace PizzeriaImpulsMVC.Domain.Interfaces
{
    public interface IReportRepository
    {
        List<Order> GenerateSalesReport(DateTime dateFrom, DateTime dateTo);
    }
}

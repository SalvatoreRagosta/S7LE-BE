using PizzeriaImpulsMVC.Domain.Interfaces;
using PizzeriaImpulsMVC.Domain.Models;

namespace PizzeriaImpulsMVC.Infrastructure.Repositories
{
    class ReportRepository : IReportRepository
    {
        private readonly Context _contex;

        public ReportRepository(Context context)
        {
            _contex = context;
        }

        public List<Order> GenerateSalesReport(DateTime dateFrom, DateTime dateTo)
        {
            var generatedSalesReport = _contex.Orders.Where(dt => dt.OrderDate >= dateFrom && dt.OrderDate <= dateTo)
                                                      .ToList();

            return generatedSalesReport;
        }
    }
}

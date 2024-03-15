namespace PizzeriaImpulsMVC.Application.ViewModels.Report
{
    public class GenerateSalesReportVm
    {
        public DateTime DateFrom { get; set; } = DateTime.Now;
        public DateTime DateTo { get; set; } = DateTime.Now;
    }
}

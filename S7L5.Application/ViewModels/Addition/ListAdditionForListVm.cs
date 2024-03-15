namespace PizzeriaImpulsMVC.Application.ViewModels.Addition
{
    public class ListAdditionForListVm
    {
        public List<AdditionForListVm>? Additions { get; set; }
        public int CurrentPage { get; set; }
        public int PageSize { get; set; }
        public string FilterString { get; set; }
        public int Count { get; set; }
    }
}

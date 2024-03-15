using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PizzeriaImpulsMVC.Infrastructure.Migrations
{
    public partial class Addpathtoitems : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ImgPath",
                table: "Pizzas",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ImgPath",
                table: "Drinks",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ImgPath",
                table: "Components",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ImgPath",
                table: "Additions",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ImgPath",
                table: "Pizzas");

            migrationBuilder.DropColumn(
                name: "ImgPath",
                table: "Drinks");

            migrationBuilder.DropColumn(
                name: "ImgPath",
                table: "Components");

            migrationBuilder.DropColumn(
                name: "ImgPath",
                table: "Additions");
        }
    }
}

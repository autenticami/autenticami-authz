resource "autenticami_acl_policy" "people-base-reader" {
    name = "people-base-reader"
    permit = [ "permit_hr_timesheet_writer_any" ]
    forbid = [ "forbid-write-hr-timesheet-writer-bc182146-1598-4fde-99aa-b2d4d08bc1e2" ]
}

resource "autenticami_acl_policy_statement" "permit_hr_timesheet_writer_any" {
  name = "permit-hr/timesheet/writer/any"

  actions = [
      "people:ReadTimesheet",
      "people:CreateTimesheet",
      "people:UpdateTimesheet",
      "people:DeleteTimesheet"
  ]
  resources = [
      "uur:581616507495:default:hr-app:organisation:people/*"
  ]
}

resource "autenticami_acl_policy_statement" "forbid-write-hr-timesheet-writer-bc182146-1598-4fde-99aa-b2d4d08bc1e2" {
  name = "forbid-write-hr/timesheet/writer/bc182146-1598-4fde-99aa-b2d4d08bc1e2"

  actions = [
    "people:Read"
  ]
  resources = [
    "uur:581616507495:default:hr-app:time-management:people/bc182146-1598-4fde-99aa-b2d4d08bc1e2"
  ]
}
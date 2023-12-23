resource "autenticami_acl_policy" "person-base-reader" {
    name = "person-base-reader"
    permit = [ "hr-timesheet-writer-any" ]
    forbid = [ "hr-timesheet-writer-bc182146-1598-4fde-99aa-b2d4d08bc1e2" ]
}

resource "autenticami_acl_policy_statement" "hr-timesheet-writer-any" {
  name = "permit-hr/timesheet/writer/any"

  actions = [
      "person:ReadTimesheet",
      "person:CreateTimesheet",
      "person:UpdateTimesheet",
      "person:DeleteTimesheet"
  ]
  resources = [
      "uur:581616507495:default:hr-app:organisation:person/*"
  ],
	condition = "DateGreaterThan({{.Autenticami.TokenIssueTime}})' && DateLessThan('{{.Autenticami.CurrentTime}}': '2023-12-31T23:59:59Z')"
}

resource "autenticami_acl_policy_statement" "hr-timesheet-writer-bc182146-1598-4fde-99aa-b2d4d08bc1e2" {
  name = "forbid-write-hr/timesheet/writer/bc182146-1598-4fde-99aa-b2d4d08bc1e2"

  actions = [
    "person:Read"
  ]
  resources = [
    "uur:581616507495:default:hr-app:time-management:person/bc182146-1598-4fde-99aa-b2d4d08bc1e2"
  ]
}

Unofficial API-Endpoints for HIBP
=================================

## DomainSearch

When using the [domain search feature](https://haveibeenpwned.com/DomainSearch) from HIBP you receive email
notifications with a token to get all breaches for all accounts within the domain.

Currently (April 2018), to get the search results for this token, the workflow and endpoints are:

* The token can be extracted from a link of the form `https://haveibeenpwned.com/DomainSearch/${token}`, which is contained in the mail from HIBP
* Trigger a mail with links to the search-result: `GET https://haveibeenpwned.com/api/multidomainsearch/${token}`
  Response should be `"ReadyForVerificationToken"`
* In the new mail, look for a link of the form `https://haveibeenpwned.com/DomainSearch/${token}/json` and `GET` it. It contains the full result of your search in json format:
```
{
    "BreachSearchResults": [ { DomainName: "...", Alias: "...", Breaches: [ <See breach model from https://haveibeenpwned.com/API/v2#BreachModel> ] }]
    "PasteSearchResults": [ { DomainName: "...", Alias: "...", Pastes: [ <See paste model from https://haveibeenpwned.com/API/v2#PasteModel> ] }]
}
```

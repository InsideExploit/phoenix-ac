function get_loading_card(loading_text)
    return [==[
{
  "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
  "type": "AdaptiveCard",
  "version": "1.0",
  "body": [
    {
      "type": "Container",
      "items": [
        {
          "type": "Image",
          "url": "]==] .. Config.cards.logo_url .. [==[",
          "size": "Large",
          "horizontalAlignment": "Center"
        },
        {
          "type": "TextBlock",
          "text": "]==] .. Config.cards.brand .. [==[",
          "size": "ExtraLarge",
          "weight": "Bolder",
          "horizontalAlignment": "Center",
          "spacing": "Small"
        },
        {
          "type": "TextBlock",
          "text": "]==] .. Config.cards.loading_subtitle .. [==[",
          "horizontalAlignment": "Center",
          "isSubtle": true,
          "spacing": "None"
        }
      ]
    },
    {
      "type": "Container",
      "spacing": "Large",
      "items": [
        {
          "type": "TextBlock",
          "text": "]==] .. loading_text .. [==[",
          "size": "ExtraLarge",
          "horizontalAlignment": "Center",
          "color": "Accent",
          "spacing": "Medium"
        },
        {
          "type": "TextBlock",
          "text": "]==] .. Config.cards.loading_wait .. [==[",
          "horizontalAlignment": "Center",
          "isSubtle": true
        }
      ]
    }
  ]
}]==]
end

function get_error_card(message)
    return [==[
{
  "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
  "type": "AdaptiveCard",
  "version": "1.0",
  "body": [
    {
      "type": "Container",
      "items": [
        {
          "type": "Image",
          "url": "]==] .. Config.cards.logo_url .. [==[",
          "size": "Large",
          "horizontalAlignment": "Center"
        },
        {
          "type": "TextBlock",
          "text": "]==] .. Config.cards.error_title .. [==[",
          "size": "ExtraLarge",
          "weight": "Bolder",
          "horizontalAlignment": "Center",
          "spacing": "Medium"
        },
        {
          "type": "TextBlock",
          "text": "]==] .. (message or Config.cards.error_fallback) .. [==[",
          "horizontalAlignment": "Center",
          "isSubtle": true,
          "spacing": "Small",
          "wrap": true
        },
        {
          "type": "TextBlock",
          "text": " ",
          "spacing": "ExtraLarge"
        }
      ]
    }
  ]
}]==]
end
